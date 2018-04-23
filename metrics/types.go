package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// This file defines utility metrics structures that allow a snapshot
// of values to be displayed on the index page.

type counter struct {
	v  int
	c  prometheus.Counter
	mx sync.Mutex
}

func (c *counter) Inc() {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.v++
	c.c.Inc()
}

func (c *counter) Get() int {
	c.mx.Lock()
	defer c.mx.Unlock()
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
	v  float64
	g  prometheus.Gauge
	mx sync.Mutex
}

func (g *gauge) Inc() {
	g.mx.Lock()
	defer g.mx.Unlock()
	g.v++
	g.g.Inc()
}

func (g *gauge) Dec() {
	g.mx.Lock()
	defer g.mx.Unlock()
	g.v--
	g.g.Dec()
}

func (g *gauge) Get() float64 {
	g.mx.Lock()
	defer g.mx.Unlock()
	return g.v
}

func (g *gauge) Set(v float64) {
	g.mx.Lock()
	defer g.mx.Unlock()
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
