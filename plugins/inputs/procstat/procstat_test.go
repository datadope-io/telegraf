package procstat

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elastic/gosigar/sys/linux"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/testutil"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	execCommand = mockExecCommand
}
func mockExecCommand(arg0 string, args ...string) *exec.Cmd {
	args = append([]string{"-test.run=TestMockExecCommand", "--", arg0}, args...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Stderr = os.Stderr
	return cmd
}
func TestMockExecCommand(t *testing.T) {
	var cmd []string
	for _, arg := range os.Args {
		if string(arg) == "--" {
			cmd = []string{}
			continue
		}
		if cmd == nil {
			continue
		}
		cmd = append(cmd, string(arg))
	}
	if cmd == nil {
		return
	}
	cmdline := strings.Join(cmd, " ")

	if cmdline == "systemctl show TestGather_systemdUnitPIDs" {
		fmt.Printf(`PIDFile=
GuessMainPID=yes
MainPID=11408
ControlPID=0
ExecMainPID=11408
`)
		os.Exit(0)
	}

	fmt.Printf("command not found\n")
	os.Exit(1)
}

type testPgrep struct {
	pids []PID
	err  error
}

func pidFinder(pids []PID, err error) func() (PIDFinder, error) {
	return func() (PIDFinder, error) {
		return &testPgrep{
			pids: pids,
			err:  err,
		}, nil
	}
}

func (pg *testPgrep) PidFile(path string) ([]PID, error) {
	return pg.pids, pg.err
}

func (p *testProc) Cmdline() (string, error) {
	return "test_proc", nil
}

func (pg *testPgrep) Pattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

// nolint
func (pg *testPgrep) Uid(user string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *testPgrep) FullPattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

type testProc struct {
	pid  PID
	ppid PID
	tags map[string]string
}

func newTestProc(pid PID) (Process, error) {
	proc := &testProc{
		tags: make(map[string]string),
	}
	return proc, nil
}

func (p *testProc) Ppid() (PID, error) {
	return p.ppid, nil
}

func (p *testProc) PID() PID {
	return p.pid
}

func (p *testProc) Username() (string, error) {
	return "testuser", nil
}

func (p *testProc) Tags() map[string]string {
	return p.tags
}

func (p *testProc) PageFaults() (*process.PageFaultsStat, error) {
	return &process.PageFaultsStat{}, nil
}

func (p *testProc) IOCounters() (*process.IOCountersStat, error) {
	return &process.IOCountersStat{}, nil
}

func (p *testProc) MemoryInfo() (*process.MemoryInfoStat, error) {
	return &process.MemoryInfoStat{}, nil
}

func (p *testProc) Name() (string, error) {
	return "test_proc", nil
}

func (p *testProc) NumCtxSwitches() (*process.NumCtxSwitchesStat, error) {
	return &process.NumCtxSwitchesStat{}, nil
}

func (p *testProc) NumFDs() (int32, error) {
	return 0, nil
}

func (p *testProc) NumThreads() (int32, error) {
	return 0, nil
}

func (p *testProc) Percent(interval time.Duration) (float64, error) {
	return 0, nil
}

func (p *testProc) MemoryPercent() (float32, error) {
	return 0, nil
}

func (p *testProc) CreateTime() (int64, error) {
	return 0, nil
}

func (p *testProc) Times() (*cpu.TimesStat, error) {
	return &cpu.TimesStat{}, nil
}

func (p *testProc) RlimitUsage(gatherUsage bool) ([]process.RlimitStat, error) {
	return []process.RlimitStat{}, nil
}

var pid PID = PID(42)
var exe string = "foo"

func TestGather_CreateProcessErrorOk(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess: func(PID) (Process, error) {
			return nil, fmt.Errorf("createProcess error")
		},
	}
	require.NoError(t, acc.GatherError(p.Gather))
}

func TestGather_CreatePIDFinderError(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		createPIDFinder: func() (PIDFinder, error) {
			return nil, fmt.Errorf("createPIDFinder error")
		},
		createProcess: newTestProc,
	}
	require.Error(t, acc.GatherError(p.Gather))
}

func TestGather_ProcessName(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		ProcessName:     "custom_name",
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.Equal(t, "custom_name", acc.TagValue("procstat", "process_name"))
}

func TestGather_NoProcessNameUsesReal(t *testing.T) {
	var acc testutil.Accumulator
	pidx := PID(os.Getpid())

	p := Procstat{
		Exe:             exe,
		createPIDFinder: pidFinder([]PID{pidx}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.True(t, acc.HasTag("procstat", "process_name"))
}

func TestGather_NoPidTag(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))
	assert.True(t, acc.HasInt32Field("procstat", "pid"))
	assert.False(t, acc.HasTag("procstat", "pid"))
}

func TestGather_PidTag(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		PidTag:          true,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))
	assert.Equal(t, "42", acc.TagValue("procstat", "pid"))
	assert.False(t, acc.HasInt32Field("procstat", "pid"))
}

func TestGather_Prefix(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		Prefix:          "custom_prefix",
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))
	assert.True(t, acc.HasInt32Field("procstat", "custom_prefix_num_fds"))
}

func TestGather_Exe(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		Exe:             exe,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.Equal(t, exe, acc.TagValue("procstat", "exe"))
}

func TestGather_User(t *testing.T) {
	var acc testutil.Accumulator
	user := "ada"

	p := Procstat{
		User:            user,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.Equal(t, user, acc.TagValue("procstat", "user"))
}

func TestGather_Pattern(t *testing.T) {
	var acc testutil.Accumulator
	pattern := "foo"

	p := Procstat{
		Pattern:         pattern,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.Equal(t, pattern, acc.TagValue("procstat", "pattern"))
}

func TestGather_MissingPidMethod(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.Error(t, acc.GatherError(p.Gather))
}

func TestGather_PidFile(t *testing.T) {
	var acc testutil.Accumulator
	pidfile := "/path/to/pidfile"

	p := Procstat{
		PidFile:         pidfile,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   newTestProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.Equal(t, pidfile, acc.TagValue("procstat", "pidfile"))
}

func TestGather_PercentFirstPass(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())

	p := Procstat{
		Pattern:         "foo",
		PidTag:          true,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   NewProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))

	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.False(t, acc.HasFloatField("procstat", "cpu_usage"))
}

func TestGather_PercentSecondPass(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())

	p := Procstat{
		Pattern:         "foo",
		PidTag:          true,
		createPIDFinder: pidFinder([]PID{pid}, nil),
		createProcess:   NewProc,
	}
	require.NoError(t, acc.GatherError(p.Gather))
	require.NoError(t, acc.GatherError(p.Gather))

	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_usage"))
}

func TestGather_systemdUnitPIDs(t *testing.T) {
	p := Procstat{
		createPIDFinder: pidFinder([]PID{}, nil),
		SystemdUnit:     "TestGather_systemdUnitPIDs",
	}
	var acc testutil.Accumulator
	pids, tags, err := p.findPids(&acc)
	require.NoError(t, err)
	assert.Equal(t, []PID{11408}, pids)
	assert.Equal(t, "TestGather_systemdUnitPIDs", tags["systemd_unit"])
}

func TestGather_cgroupPIDs(t *testing.T) {
	//no cgroups in windows
	if runtime.GOOS == "windows" {
		t.Skip("no cgroups in windows")
	}
	td, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(td)
	err = ioutil.WriteFile(filepath.Join(td, "cgroup.procs"), []byte("1234\n5678\n"), 0644)
	require.NoError(t, err)

	p := Procstat{
		createPIDFinder: pidFinder([]PID{}, nil),
		CGroup:          td,
	}
	var acc testutil.Accumulator
	pids, tags, err := p.findPids(&acc)
	require.NoError(t, err)
	assert.Equal(t, []PID{1234, 5678}, pids)
	assert.Equal(t, td, tags["cgroup"])
}

func TestProcstatLookupMetric(t *testing.T) {
	p := Procstat{
		createPIDFinder: pidFinder([]PID{543}, nil),
		Exe:             "-Gsys",
	}
	var acc testutil.Accumulator
	err := acc.GatherError(p.Gather)
	require.NoError(t, err)
	require.Equal(t, len(p.procs)+1, len(acc.Metrics))
}

func TestAddConnectionEndpoints(t *testing.T) {
	tests := []struct {
		name        string
		pid         PID
		ppid        PID
		listenPorts map[uint32]interface{}
		tcp         map[uint32][]ConnInfo
		publicIPs   []net.IP
		privateIPs  []net.IP
		metrics     []telegraf.Metric
		err         string
	}{
		{
			name: "no connections, no metrics",
		},
		{
			name:        "outside connection",
			pid:         100,
			listenPorts: map[uint32]interface{}{},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 34567,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 80,
						state:   linux.TCP_ESTABLISHED,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPConnectionKey: "1.1.1.1:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "TCP states except SYN_SENT are used for connections",
			pid:         100,
			listenPorts: map[uint32]interface{}{},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10000,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 80,
						state:   linux.TCP_ESTABLISHED,
					},
					{ // this is ignore, is a host trying to connect but the other end has not replied
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10001,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 81,
						state:   linux.TCP_SYN_SENT,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10002,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 82,
						state:   linux.TCP_SYN_RECV,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10003,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 83,
						state:   linux.TCP_FIN_WAIT1,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10004,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 84,
						state:   linux.TCP_FIN_WAIT2,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10005,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 85,
						state:   linux.TCP_TIME_WAIT,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10006,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 86,
						state:   linux.TCP_CLOSE,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10007,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 87,
						state:   linux.TCP_CLOSE_WAIT,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10008,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 88,
						state:   linux.TCP_LAST_ACK,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 10009,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 89,
						state:   linux.TCP_CLOSING,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPConnectionKey: "1.1.1.1:80,1.1.1.1:82,1.1.1.1:83,1.1.1.1:84,1.1.1.1:85,1.1.1.1:86,1.1.1.1:87,1.1.1.1:88,1.1.1.1:89",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "IPv4 listener",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{net.ParseIP("192.168.0.2")},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "process listening in a IP not present in the local IPs will generate metric anyway",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "process listening in a port not present in the listeners list will generate metric anyway",
			pid:         100,
			listenPorts: map[uint32]interface{}{},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "IPv6 listener",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("dead::beef"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "[dead::beef]:80",
					},
					time.Now(),
				),
			},
		},
		{
			name: "private IPv4 listener do not generate metrics",
			pid:  100,
			listenPorts: map[uint32]interface{}{
				80: nil,
			},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{net.ParseIP("192.168.0.2")},
			metrics:    []telegraf.Metric{},
		},
		{
			name:        "private IPv6 listener do not generate metrics",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("dead::beef"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{net.ParseIP("dead::beef")},
			metrics:    []telegraf.Metric{},
		},
		{
			name:        "0.0.0.0 listener listen in all public IPv4s",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("0.0.0.0"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{net.ParseIP("192.168.0.2"), net.ParseIP("10.10.0.2"), net.ParseIP("dead::beef")},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "10.10.0.2:80,192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        ":: listener listen in all public IPv4 and IPv6s",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("::"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{net.ParseIP("192.168.0.2"), net.ParseIP("10.10.0.2"), net.ParseIP("dead::beef")},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "10.10.0.2:80,192.168.0.2:80,[dead::beef]:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "ignore listeners in loopback IPs",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("127.0.0.1"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics:    []telegraf.Metric{},
		},
		{
			name:        "ignore connections from external hosts to local listeners",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("127.0.0.1"),
						srcPort: 80,
						dstIP:   net.ParseIP("54.89.89.54"),
						dstPort: 30123,
						state:   linux.TCP_ESTABLISHED,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics:    []telegraf.Metric{},
		},
		{
			name:        "ignore connections from internal procs to other internal procs using the public IPs",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 30000,
						dstIP:   net.ParseIP("192.168.0.2"),
						dstPort: 80,
						state:   linux.TCP_ESTABLISHED,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{net.ParseIP("192.168.0.2")},
			metrics:    []telegraf.Metric{},
		},
		{ // We are testing how behaves addConnectionEnpoints it if received a "pid not found" kind of error
			name:        "proc without network info does not generates an error, nor metrics",
			pid:         100,
			listenPorts: map[uint32]interface{}{},
			tcp:         map[uint32][]ConnInfo{},
			publicIPs:   []net.IP{},
			privateIPs:  []net.IP{},
			metrics:     []telegraf.Metric{},
		},
		{
			name: "process listening in two differents ports using :: with differents public IPs",
		},
		{ // same schema valid for: apache httpd, php-fpm, 
			name: "service with a parent process and several child, only the parent should report the listeners, parent case (nginx style)",
			pid:  101, // parent
			listenPorts: map[uint32]interface{}{
				80: nil,
			},
			tcp: map[uint32][]ConnInfo{
				100: { // parent
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
				101: { // child
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name: "service with a parent process and several child, only the parent should report the listeners, child case (nginx style)",
			pid:  101, // child
			ppid: 100,
			listenPorts: map[uint32]interface{}{
				80: nil,
			},
			tcp: map[uint32][]ConnInfo{
				100: { // parent
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
				101: { // child
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics:    []telegraf.Metric{},
		},
		{
			name: "child process listening in parent process plus other port, generate metric with the extra listener",
			pid:  101, // child
			ppid: 100,
			listenPorts: map[uint32]interface{}{
				80:  nil,
				443: nil,
			},
			tcp: map[uint32][]ConnInfo{
				100: { // parent
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
				101: { // child
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 443,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "192.168.0.2:443",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "process listening in 0.0.0.0 and also in some IPv4 address, avoid duplication",
			pid:         100,
			listenPorts: map[uint32]interface{}{80: nil},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("0.0.0.0"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
					{
						srcIP:   net.ParseIP("172.17.0.1"),
						srcPort: 80,
						state:   linux.TCP_LISTEN,
					},
				},
			},
			publicIPs:  []net.IP{net.ParseIP("192.168.0.2"), net.ParseIP("10.10.0.2"), net.ParseIP("dead::beef")},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPListenKey: "10.10.0.2:80,172.17.0.1:80,192.168.0.2:80",
					},
					time.Now(),
				),
			},
		},
		{
			name:        "avoid duplication in outboun connections",
			pid:         100,
			listenPorts: map[uint32]interface{}{},
			tcp: map[uint32][]ConnInfo{
				100: {
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 34567,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 80,
						state:   linux.TCP_ESTABLISHED,
					},
					{
						srcIP:   net.ParseIP("192.168.0.2"),
						srcPort: 34568,
						dstIP:   net.ParseIP("1.1.1.1"),
						dstPort: 80,
						state:   linux.TCP_ESTABLISHED,
					},
				},
			},
			publicIPs:  []net.IP{},
			privateIPs: []net.IP{},
			metrics: []telegraf.Metric{
				testutil.MustMetric(
					MetricNameTCPConnections,
					map[string]string{},
					map[string]interface{}{
						TCPConnectionKey: "1.1.1.1:80",
					},
					time.Now(),
				),
			},
		},
		{
			name: "TODO POR AQUI definir casuisticas de procesos, parent-child, postgres, oracle, etc",
		},
		// TODO support to resolve docker procs
		/*
			{
				name: "listener process inside a docker container with port exposed via docker-proxy should return the docker-proxy port",
			},
		*/
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var acc testutil.Accumulator

			proc := &testProc{
				pid:  test.pid,
				ppid: test.ppid,
			}

			netInfo := NetworkInfo{
				tcp:         test.tcp,
				listenPorts: test.listenPorts,
				publicIPs:   test.publicIPs,
				privateIPs:  test.privateIPs,
			}

			err := addConnectionEnpoints(&acc, proc, netInfo)
			if err != nil {
				assert.EqualError(t, err, test.err)
				//assert.FailNowf(t, "error calling addConnectionEnpoints", err.Error())
			}

			// Function has generated the same number of metrics defined in the test
			assert.Len(t, acc.GetTelegrafMetrics(), len(test.metrics))

			for _, m := range test.metrics {
				for _, value := range m.FieldList() {
					assert.Truef(
						t,
						acc.HasPoint(m.Name(), m.Tags(), value.Key, value.Value),
						"Missing point: %s,%v %s=%s\nMetrics: %v",
						m.Name(),
						m.Tags(),
						value.Key,
						value.Value,
						acc.GetTelegrafMetrics(),
					)
				}
			}
		})
	}
}

// TODO testear la función getLocalIps
/*
	{
		name: "ignore point to point interfaces",
	},
	{
		name: "ignore IPs in virtual interfaces",
	},
	{
		name: "firewall rules redirecting a port to some process (docker without docker-proxy nor net=host)",
	},
*/
