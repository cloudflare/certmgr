package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/kisom/goutils/lib"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s [-a addresses] [-c chunksize] [-h] [-u user] command args

Flags:
        -a addresses    The comma-separated list of servers to send
                        to. There must not be any spaces in this list.

        -c chunk        The size of chunks to transfer, in bytes. The
                        default is 16MB.

        -u user         The SSH username to use. It must be the
                        same for all hosts. Defaults to the value
                        of the USER environment variable.

Commands:
	exec, run: run a command on the servers
        The args list must be the command line to send to the hosts.

	upload, up, push, send: upload a file to the servers
        The first argument is the local file to upload, and the second
        is the filename to store it as on the remote.

	download, down, pull, fetch: download a file from the servers
        The first argument is the filename to fetch.The second argument
        is the base name for the local file. It will have a '-' and the
        hostname appended.

`, lib.ProgName())
}

var chunkSize = 16777216

var modes = ssh.TerminalModes{
	ssh.ECHO:          0,
	ssh.TTY_OP_ISPEED: 14400,
	ssh.TTY_OP_OSPEED: 14400,
}

func sshAgent() ssh.AuthMethod {
	a, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(a).Signers)
	}

	lib.Err(lib.ExitFailure, err, "failed to authenticate with SSH agent")
	return nil
}

func sshConfig(user string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			sshAgent(),
		},
	}
}

func scanner(host string, in io.Reader, out io.Writer) {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(out, "[%s] %s\n", host, line)
	}
}

func logError(host string, err error, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] FAILED: %s: %v\n", host, msg, err)
}

func exec(wg *sync.WaitGroup, user, host string, commands []string) {
	var shutdown []func() error

	defer func() {
		for i := len(shutdown) - 1; i >= 0; i-- {
			err := shutdown[i]()
			if err != nil && err != io.EOF {
				logError(host, err, "shutting down")
			}
		}
	}()
	defer wg.Done()

	conf := sshConfig(user)
	conn, err := ssh.Dial("tcp", host+":22", conf)
	if err != nil {
		logError(host, err, "failed to connect")
		return
	}
	shutdown = append(shutdown, conn.Close)

	session, err := conn.NewSession()
	if err != nil {
		logError(host, err, "failed to establish session")
		return
	}
	shutdown = append(shutdown, session.Close)

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		logError(host, err, "request for pty failed")
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		logError(host, err, "failed to setup standard output")
		return
	}
	go scanner(host, stdout, os.Stdout)

	stderr, err := session.StderrPipe()
	if err != nil {
		logError(host, err, "failed to setup standard error")
		return
	}
	go scanner(host, stderr, os.Stderr)

	for _, command := range commands {
		err = session.Run(command)
		if err != nil {
			logError(host, err, "running command failed")
			return
		}
	}
}

func upload(wg *sync.WaitGroup, user, host, local, remote string) {
	var shutdown []func() error

	defer func() {
		for i := len(shutdown) - 1; i >= 0; i-- {
			err := shutdown[i]()
			if err != nil && err != io.EOF {
				logError(host, err, "shutting down")
			}
		}
	}()
	defer wg.Done()

	conf := sshConfig(user)
	conn, err := ssh.Dial("tcp", host+":22", conf)
	if err != nil {
		logError(host, err, "failed to connect")
		return
	}
	shutdown = append(shutdown, conn.Close)

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		logError(host, err, "setting up SFTP client")
		return
	}
	shutdown = append(shutdown, sftp.Close)

	remoteFile, err := sftp.Create(remote)
	if err != nil {
		logError(host, err, "creating file %s on remote", remote)
		return
	}
	shutdown = append(shutdown, remoteFile.Close)

	localFile, err := os.Open(local)
	if err != nil {
		logError(host, err, "opening local file")
		return
	}
	shutdown = append(shutdown, localFile.Close)

	var buf = make([]byte, chunkSize)
	for {
		var n int
		n, err = localFile.Read(buf)
		if n > 0 {
			_, err = remoteFile.Write(buf[:n])
			if err != nil {
				logError(host, err, "writing chunk")
				return
			}
			fmt.Printf("[%s] wrote %d-byte chunk\n", host, n)
		}

		if err == io.EOF {
			break
		} else if err != nil {
			logError(host, err, "reading chunk")
			return
		}
	}
	fmt.Printf("[%s] %s uploaded to %s\n", host, remote, local)
}

func download(wg *sync.WaitGroup, user, host, local, remote string) {
	var shutdown []func() error

	defer func() {
		for i := len(shutdown) - 1; i >= 0; i-- {
			err := shutdown[i]()
			if err != nil && err != io.EOF {
				logError(host, err, "shutting down")
			}
		}
	}()
	defer wg.Done()

	conf := sshConfig(user)
	conn, err := ssh.Dial("tcp", host+":22", conf)
	if err != nil {
		logError(host, err, "failed to connect")
		return
	}
	shutdown = append(shutdown, conn.Close)

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		logError(host, err, "setting up SFTP client")
		return
	}
	shutdown = append(shutdown, sftp.Close)

	remoteFile, err := sftp.Open(remote)
	if err != nil {
		logError(host, err, "opening file %s on remote", remote)
		return
	}
	shutdown = append(shutdown, remoteFile.Close)

	local = local + "-" + host
	localFile, err := os.Create(local)
	if err != nil {
		logError(host, err, "opening local file")
		return
	}
	shutdown = append(shutdown, localFile.Close)

	var buf = make([]byte, chunkSize)
	for {
		var n int
		n, err = remoteFile.Read(buf)
		if n > 0 {
			_, err = localFile.Write(buf[:n])
			if err != nil {
				logError(host, err, "writing chunk")
				return
			}
			fmt.Printf("[%s] wrote %d-byte chunk\n", host, n)
		}

		if err == io.EOF {
			break
		} else if err != nil {
			logError(host, err, "reading chunk")
			return
		}
	}
	fmt.Printf("[%s] %s downloaded to %s\n", host, remote, local)
}

func init() {
	flag.Usage = func() {
		usage(os.Stdout)
	}
}

func main() {
	var hostsFlag, user string
	flag.StringVar(&hostsFlag, "a", "", "`hosts` to run on")
	flag.IntVar(&chunkSize, "c", chunkSize, "`size` in bytes of transfer chunks")
	flag.StringVar(&user, "u", os.Getenv("USER"), "`username` to run commands as")
	flag.Parse()

	hosts := strings.Split(hostsFlag, ",")
	if len(hosts) == 0 {
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		usage(os.Stderr)
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	var wg = new(sync.WaitGroup)

	switch cmd {
	case "exec", "run":
		if flag.NArg() < 2 {
			usage(os.Stderr)
			os.Exit(1)
		}

		commands := []string{strings.Join(flag.Args()[1:], " ")}
		for _, host := range hosts {
			wg.Add(1)
			go exec(wg, user, host, commands)
		}
	case "upload", "up", "push", "send":
		if flag.NArg() != 3 {
			usage(os.Stderr)
			os.Exit(1)
		}

		for _, host := range hosts {
			wg.Add(1)
			go upload(wg, user, host, flag.Arg(1), flag.Arg(2))
		}
	case "download", "down", "pull", "fetch":
		if flag.NArg() != 3 {
			usage(os.Stderr)
			os.Exit(1)
		}

		for _, host := range hosts {
			wg.Add(1)
			go download(wg, user, host, flag.Arg(2), flag.Arg(1))
		}
	case "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %s.\n", cmd)
		usage(os.Stderr)
		os.Exit(1)
	}

	log.Printf("waiting for sessions to complete")
	wg.Wait()
}
