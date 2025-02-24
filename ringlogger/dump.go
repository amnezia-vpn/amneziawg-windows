/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/euphoria-windows/conf"
)

func DumpTo(out io.Writer, notSystem bool) error {
	root, err := conf.RootDirectory(!notSystem)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "log.bin")
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	mapping, err := windows.CreateFileMapping(windows.Handle(file.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	rl, err := newRingloggerFromMappingHandle(mapping, "DMP", windows.FILE_MAP_READ)
	if err != nil {
		windows.CloseHandle(mapping)
		return err
	}
	defer rl.Close()
	_, err = rl.WriteTo(out)
	if err != nil {
		return err
	}
	return nil
}
