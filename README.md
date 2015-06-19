# Telegraf - A native agent for InfluxDB

Telegraf is an agent written in Go for collecting metrics from the system it's running on or from other services and writing them into InfluxDB.

Design goals are to have a minimal memory footprint with a plugin system so that developers in the community can easily add support for collecting metrics from well known services (like Hadoop, or Postgres, or Redis) and third party APIs (like Mailchimp, AWS CloudWatch, or Google Analytics).

We'll eagerly accept pull requests for new plugins and will manage the set of plugins that Telegraf supports. See the bottom of this doc for instructions on writing new plugins.

## Quickstart

* Build from source or download telegraf. Packages here:

```
http://get.influxdb.org/telegraf/telegraf_0.1.1_amd64.deb
http://get.influxdb.org/telegraf/telegraf-0.1.1-1.x86_64.rpm
```

* Run `telegraf -sample-config > telegraf.toml` to create an initial configuration
* Edit the configuration to match your needs
* Run `telegraf -config telegraf.toml -test` to output one full measurement sample to STDOUT
* Run `telegraf -config telegraf.toml` to gather and send metrics to InfluxDB

## Telegraf Options

Telegraf has a few options you can configure under the `agent` section of the config. If you don't see an `agent` section run `telegraf -sample-config > telegraf.toml` to create a valid initial configuration:

* **hostname**: The hostname is passed as a tag. By default this will be the value retured by `hostname` on the machine running Telegraf. You can override that value here.
* **interval**: How ofter to gather metrics. Uses a simple number + unit parser, ie "10s" for 10 seconds or "5m" for 5 minutes.
* **debug**: Set to true to gather and send metrics to STDOUT as well as InfluxDB.

## Supported Plugins

Telegraf currently has support for collecting metrics from:

* System (memory, CPU, network, etc.)
* Docker
* MySQL
* PostgreSQL
* Redis

We'll be adding support for many more over the coming months. Read on if you want to add support for another service or third-party API.

## Plugin Options

There are 3 configuration options that are configurable per plugin:

* **pass**: An array of strings that is used to filter metrics generated by the current plugin. Each string in the array is tested as a prefix against metrics and if it matches, the metric is emitted.
* **drop**: The inverse of pass, if a metric matches, it is not emitted.
* **interval**: How often to gather this metric. Normal plugins use a single global interval, but if one particular plugin should be run less or more often, you can configure that here.

## Plugins

This section is for developers that want to create new collection plugins. Telegraf is entirely plugin driven. This interface allows for operators to
pick and chose what is gathered as well as makes it easy for developers
to create new ways of generating metrics.

Plugin authorship is kept as simple as possible to promote people to develop
and submit new plugins.

## Guidelines

* A plugin must conform to the `plugins.Plugin` interface.
* Telegraf promises to run each plugin's Gather function serially. This means
developers don't have to worry about thread safety within these functions.
* Each generated metric automatically has the name of the plugin that generated
it prepended. This is to keep plugins honest.
* Plugins should call `plugins.Add` in their `init` function to register themselves.
See below for a quick example.
* To be available within Telegraf itself, plugins must add themselves to the `github.com/influxdb/telegraf/plugins/all/all.go` file.
* The `SampleConfig` function should return valid toml that describes how the plugin can be configured. This is include in `telegraf -sample-config`.
* The `Description` function should say in one line what this plugin does.

### Plugin interface

```go
type Plugin interface {
  SampleConfig() string
  Description() string
  Gather(Accumulator) error
}

type Accumulator interface {
  Add(measurement string, value interface{}, tags map[string]string)
  AddValuesWithTime(measurement string, values map[string]interface{}, tags map[string]string, timestamp time.Time)
}
```

### Accumulator

The way that a plugin emits metrics is by interacting with the Accumulator.

The `Add` function takes 3 arguments:
* **measurement**: A string description of the metric. For instance `bytes_read` or `faults`.
* **value**: A value for the metric. This accepts 5 different types of value:
  * **int**: The most common type. All int types are accepted but favor using `int64`
  Useful for counters, etc.
  * **float**: Favor `float64`, useful for gauges, percentages, etc.
  * **bool**: `true` or `false`, useful to indicate the presence of a state. `light_on`, etc.
  * **string**: Typically used to indicate a message, or some kind of freeform information.
  * **time.Time**: Useful for indicating when a state last occurred, for instance `light_on_since`.
* **tags**: This is a map of strings to strings to describe the where or who about the metric. For instance, the `net` plugin adds a tag named `"interface"` set to the name of the network interface, like `"eth0"`.

The `AddValuesWithTime` allows multiple values for a point to be passed. The values
used are the same type profile as **value** above. The **timestamp** argument
allows a point to be registered as having occurred at an arbitrary time.

Let's say you've written a plugin that emits metrics about processes on the current host.

```go

type Process struct {
  CPUTime float64
  MemoryBytes int64
  PID int
}

func Gather(acc plugins.Accumulator) error {
  for _, process := range system.Processes() {
    tags := map[string]string {
      "pid": fmt.Sprintf("%d", process.Pid),
    }

    acc.Add("cpu", process.CPUTime, tags)
    acc.Add("memoory", process.MemoryBytes, tags)
  }
}
```

### Example

```go

// simple.go

import "github.com/influxdb/telegraf/plugins"

type Simple struct {
  Ok bool
}

func (s *Simple) Description() string {
  return "a demo plugin"
}

func (s *Simple) SampleConfig() string {
  return "ok = true # indicate if everything is fine"
}

func (s *Simple) Gather(acc plugins.Accumulator) error {
  if s.Ok {
    acc.Add("state", "pretty good", nil)
  } else {
    acc.Add("state", "not great", nil)
  }

  return nil
}

func init() {
  plugins.Add("simple", func() plugins.Plugin { &Simple{} })
}
```

