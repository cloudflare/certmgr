package metrics

import "github.com/prometheus/client_golang/prometheus"

// This file defines utility metrics structures that allow a snapshot
// of values to be displayed on the index page.

type counter struct {
	v int
	c prometheus.Counter
}

func (c *counter) Inc() {
	c.v++
	c.c.Inc()
}

func (c *counter) Get() int {
	return c.v
}

func (c *counter) register() {
	prometheus.MustRegister(c.c)
}

func newCounter(name, help string) *counter {
	opts := prometheus.CounterOpts{
		Name: name,
		Help: help,
	}

	c := &counter{
		c: prometheus.NewCounter(opts),
	}

	c.register()
	return c
}

type gauge struct {
	v float64
	g prometheus.Gauge
}

func (g *gauge) Inc() {
	g.v++
	g.g.Inc()
}

func (g *gauge) Dec() {
	g.v--
	g.g.Dec()
}

func (g *gauge) Get() float64 {
	return g.v
}

func (g *gauge) Set(v float64) {
	g.v = v
	g.g.Set(v)
}

func (g *gauge) register() {
	prometheus.MustRegister(g.g)
}

func newGauge(name, help string) *gauge {
	opts := prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}

	g := &gauge{
		g: prometheus.NewGauge(opts),
	}

	g.register()
	return g
}
