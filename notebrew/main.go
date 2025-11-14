package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bokwoon95/nbi2"
	"github.com/bokwoon95/sqddl/ddl"
)

func main() {
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHomeDir := os.Getenv("XDG_CONFIG_HOME")
		if configHomeDir == "" {
			configHomeDir = homeDir
		}
		dataHomeDir := os.Getenv("XDG_DATA_HOME")
		if dataHomeDir == "" {
			dataHomeDir = homeDir
		}
		var configDir string
		var verbose bool
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configDir, "configdir", "", "")
		flagset.BoolVar(&verbose, "verbose", false, "")
		err = flagset.Parse(os.Args[1:])
		if err != nil {
			return err
		}
		args := flagset.Args()
		if configDir == "" {
			configDir = filepath.Join(configHomeDir, "notebrew-config")
		} else {
			configDir = filepath.Clean(configDir)
		}
		err = os.MkdirAll(configDir, 0755)
		if err != nil {
			return err
		}
		configDir, err = filepath.Abs(filepath.FromSlash(configDir))
		if err != nil {
			return err
		}
		if len(args) > 0 {
			switch args[0] {
			case "config":
				cmd, err := nbi2.ConfigCommand(configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "hashpassword":
				// cmd, err := nbi2.HashpasswordCommand(args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			}
		}
		nbrew, err := nbi2.New(configDir, dataHomeDir, nil)
		if err != nil {
			return err
		}
		defer nbrew.Close()
		if nbrew.Dialect == "sqlite" {
			_, err := nbrew.DB.ExecContext(context.Background(), "PRAGMA optimize(0x10002)")
			if err != nil {
				nbrew.Logger.Error(err.Error())
			}
			ticker := time.NewTicker(4 * time.Hour)
			defer ticker.Stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				for {
					<-ticker.C
					_, err := nbrew.DB.ExecContext(ctx, "PRAGMA optimize")
					if err != nil {
						nbrew.Logger.Error(err.Error())
					}
				}
			}()
		}
		if len(args) > 0 {
			switch args[0] {
			case "createinvite":
				// cmd, err := nbi2.CreateinviteCommand(nbrew, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "createuser":
				// cmd, err := nbi2.CreateuserCommand(nbrew, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "deleteinvite":
				// cmd, err := nbi2.DeleteinviteCommand(nbrew, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "deleteuser":
				// cmd, err := nbi2.DeleteuserCommand(nbrew, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "resetpassword":
				// cmd, err := nbi2.ResetpasswordCommand(nbrew, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// return nil
			case "start":
				// cmd, err := nbi2.StartCommand(nbrew, configDir, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// cmd.Handler = nbrew
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "status":
				// cmd, err := nbi2.StatusCommand(nbrew, configDir, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			case "stop":
				// cmd, err := nbi2.StopCommand(nbrew, configDir, args[1:]...)
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				// err = cmd.Run()
				// if err != nil {
				// 	return fmt.Errorf("%s: %w", args[0], err)
				// }
				return nil
			default:
				return fmt.Errorf("unknown command: %s", args[0])
			}
		}
		server, err := nbrew.NewServer()
		if err != nil {
			return err
		}
		server.Handler = nbrew
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				return err
			}
			// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
			const WSAEADDRINUSE = syscall.Errno(10048)
			if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
				if !nbrew.CMSDomainHTTPS {
					fmt.Println("notebrew is already running on http://" + nbrew.CMSDomain + "/files/")
				} else {
					fmt.Println("notebrew is already running (run `notebrew stop` to stop the process)")
				}
				return nil
			}
			return err
		}
		wait := make(chan os.Signal, 1)
		signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		if server.Addr == ":443" {
			go http.ListenAndServe(":80", http.HandlerFunc(nbrew.RedirectToHTTPS))
			go func() {
				err := server.ServeTLS(listener, "", "")
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			fmt.Printf("notebrew is running on %s\n", server.Addr)
		} else {
			go func() {
				err := server.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if !nbrew.CMSDomainHTTPS {
				fmt.Printf("notebrew is running on %s\n", "http://"+nbrew.CMSDomain+"/files/")
			} else {
				fmt.Printf("notebrew is running on %s\n", server.Addr)
			}
		}
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	}()
	if err != nil {
		var migrationErr *ddl.MigrationError
		if errors.As(err, &migrationErr) {
			fmt.Println(migrationErr.Filename)
			fmt.Println(migrationErr.Contents)
		}
		fmt.Println(err)
		os.Exit(1)
	}
}
