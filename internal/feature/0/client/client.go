package client

import (
	"context"

	"github.com/gunawanwijaya/diego/pkg"
)

type Configuration struct {
	//
}

func (x Configuration) Validate() (err error) {
	return nil
}

type Dependency struct {
	//
}

func (x Dependency) Validate() (err error) {
	return nil
}

type Client interface {
}

type client struct {
	Configuration
	Dependency
}

func New(ctx context.Context, cfg Configuration, dep Dependency) (_ Client, err error) {
	return pkg.Validate(&client{cfg, dep})
}

func (x *client) Validate() (err error) {
	if _, err = pkg.Validate(x.Configuration); err != nil {
		return err
	}
	if _, err = pkg.Validate(x.Dependency); err != nil {
		return err
	}
	return nil
}
