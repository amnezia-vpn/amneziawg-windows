/* SPDX-License-Identifier: MIT
*
* Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/amnezia-vpn/amnezia-wg/conn"
	"github.com/amnezia-vpn/amnezia-wg/device"
	"github.com/amnezia-vpn/amnezia-wg/ipc"
	"github.com/amnezia-vpn/amnezia-wg/tun"
	"github.com/amnezia-vpn/awg-windows/conf"
	"github.com/amnezia-vpn/awg-windows/elevate"
	"github.com/amnezia-vpn/awg-windows/ringlogger"
	"github.com/amnezia-vpn/awg-windows/services"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type tunnelService struct {
	ConfString string
	TunnelName string
}

func (service *tunnelService) Execute(
	args []string,
	r <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (svcSpecificEC bool, exitCode uint32) {
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
	var dev *device.Device
	var wintun tun.Device
	var uapi net.Listener
	var nativeTun *tun.NativeTun
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println(
						"Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.",
					)
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && wintun != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if wintun != nil {
			wintun.Close()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		}
		if logErr == nil && dev != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.FromWgQuickWithUnknownEncoding(
		service.ConfString,
		service.TunnelName,
	)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	log.Printf(
		"Got config:%s\n with name:%s\n",
		service.ConfString,
		service.TunnelName,
	)

	services.PrintStarting()

	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil &&
				lockStatus.IsLocked {
				/* If we don't do this, then the driver installation will block forever, because
				* installing a network adapter starts the driver service too. Apparently at boot time,
				* Windows 8.1 locks the SCM for each service start, creating a deadlock if we don't
				* announce that we're running before starting additional services.
				 */
				log.Printf(
					"SCM locked for %v by %s, marking service as started",
					lockStatus.Age,
					lockStatus.Owner,
				)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating network adapter")
	for i := 0; i < 15; i++ {
		if i > 0 {
			time.Sleep(time.Second)
			log.Printf(
				"Retrying adapter creation after failure because system just booted (T+%v): %v",
				windows.DurationSinceBoot(),
				err,
			)
		}
		// wintun, err = driver.CreateAdapter(
		// 	config.Name,
		// 	"WireGuard",
		// 	deterministicGUID(config),
		// )
		wintun, err = tun.CreateTUNWithRequestedGUID(
			config.Name,
			deterministicGUID(config),
			0,
		)
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}

	nativeTun = wintun.(*tun.NativeTun)
	wintunVersion, err := nativeTun.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine Wintun version: %v", err)
	} else {
		log.Printf("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, nativeTun)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	// log.Println("Setting interface configuration")
	// err = wintun.SetConfiguration(config.ToDriverConfiguration())
	// if err != nil {
	// 	serviceError = services.ErrorDeviceSetConfig
	// 	return
	// }
	// err = wintun.SetAdapterState(driver.AdapterStateUp)
	// if err != nil {
	// 	serviceError = services.ErrorDeviceBringUp
	// 	return
	// }

	bind := conn.NewDefaultBind()
	dev = device.NewDevice(wintun, bind, &device.Logger{log.Printf, log.Printf})

	log.Println("Setting interface configuration")
	uapi, err = ipc.UAPIListen(config.Name)
	if err != nil {
		serviceError = services.ErrorUAPIListen
		return
	}

	uapiConf, err := config.ToUAPI()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	err = dev.IpcSet(uapiConf)
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}

	log.Println("Bringing peers up")
	dev.Up()
	watcher.Configure(bind.(conn.BindSocketToInterface), config, nativeTun)

	// watcher.Configure(adapter, config, luid)

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

func Run(confString string, tunnelName string) error {
	return svc.Run(tunnelName, &tunnelService{confString, tunnelName})
}
