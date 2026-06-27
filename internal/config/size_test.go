package config

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestConfigSize(t *testing.T) {
	cfg := Default()
	size := unsafe.Sizeof(*cfg)
	fmt.Printf("\nConfig struct size: %d bytes\n", size)
	fmt.Printf("Config fields breakdown:\n")
	fmt.Printf("  Listen (string): %d bytes\n", unsafe.Sizeof(cfg.Listen))
	fmt.Printf("  DataDir (string): %d bytes\n", unsafe.Sizeof(cfg.DataDir))
	fmt.Printf("  AllowedHosts ([]string): %d bytes\n", unsafe.Sizeof(cfg.AllowedHosts))
	fmt.Printf("  Ports (struct): %d bytes\n", unsafe.Sizeof(cfg.Ports))
	fmt.Printf("  Clash (struct): %d bytes\n", unsafe.Sizeof(cfg.Clash))
	fmt.Printf("  SingBox (struct): %d bytes\n", unsafe.Sizeof(cfg.SingBox))
	fmt.Printf("  Updater (struct): %d bytes\n", unsafe.Sizeof(cfg.Updater))
}
