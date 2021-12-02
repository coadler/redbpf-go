package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln("remove memlock:", err)
	}

	fi, err := os.ReadFile("../../target/bpf/programs/openmonitor/openmonitor.elf")
	if err != nil {
		log.Fatalln("read elf:", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fi))
	if err != nil {
		log.Fatalln("load spec:", err)
	}

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatalln("load and assign:", err)
	}
	defer objs.Close()

	log.Println("successfully loaded!")
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfMaps struct {
	KprobeMap *ebpf.Map `ebpf:"open_paths"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.KprobeMap,
	)
}

type bpfPrograms struct {
	KprobeOpenat2 *ebpf.Program `ebpf:"outer_do_sys_openat2"`
}

func (p *bpfPrograms) Close() error {
	return bpfClose(
		p.KprobeOpenat2,
	)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
