package authorization

import (
	"context"

	"github.com/gunawanwijaya/diego/pkg"
)

type Configuration struct {
	//
}

func (x Configuration) Validate() (err error) {
	return pkg.ErrUnimplemented
}

type Dependency struct {
	CipherRoot pkg.Cipher
}

func (x Dependency) Validate() (err error) {
	if _, err = pkg.Validate(x.CipherRoot); err != nil {
		return err
	}
	return pkg.ErrUnimplemented
}

type Authorization interface {
}

type authorization struct {
	Configuration
	Dependency
}

func New(ctx context.Context, cfg Configuration, dep Dependency) (_ Authorization, err error) {
	return pkg.Validate(&authorization{cfg, dep})
}

func (x *authorization) Validate() (err error) {
	if _, err = pkg.Validate(x.Configuration); err != nil {
		return err
	}
	if _, err = pkg.Validate(x.Dependency); err != nil {
		return err
	}
	return nil
}
