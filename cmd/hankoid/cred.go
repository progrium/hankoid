package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/progrium/hankoid/credhelper"
	"github.com/spf13/cobra"
)

// The client side of device sign-in: "hankoid login URL" approves this machine for a resource,
// and "hankoid cred get URL" is a credential helper in the shape of hyper9's design 0119.

func credHelper(path string) (*credhelper.Helper, error) {
	if path == "" {
		if v := os.Getenv("HANKOID_CREDENTIALS"); v != "" {
			path = v
		} else {
			var err error
			if path, err = credhelper.DefaultPath(); err != nil {
				return nil, err
			}
		}
	}
	return &credhelper.Helper{Path: path}, nil
}

func registerCredCommands(root *cobra.Command) {
	var path string
	pathFlag := func(c *cobra.Command) {
		c.Flags().StringVar(&path, "credentials", "", "credentials file (default $HANKOID_CREDENTIALS or ~/.config/hankoid/credentials.json)")
		c.SilenceUsage = true
	}

	var opts credhelper.LoginOptions
	login := &cobra.Command{
		Use:   "login URL",
		Short: "Sign this machine in to a resource (such as a 9P server) with device sign-in",
		Long: `login starts device sign-in for the resource at URL and waits while you approve
it in a browser. The resource's metadata names the issuer and client; pass --issuer and
--client for a resource that doesn't publish it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := credHelper(path)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			opts.Out = os.Stderr
			c, err := h.Login(ctx, args[0], opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Signed in to %s.\n", c.Resource)
			return nil
		},
	}
	login.Flags().StringVar(&opts.Issuer, "issuer", "", "OIDC issuer URL")
	login.Flags().StringVar(&opts.ClientID, "client", "", "device client ID")
	login.Flags().StringVar(&opts.DeviceName, "name", "", "name for this device on the approval page (default the hostname)")

	logout := &cobra.Command{
		Use:   "logout URL",
		Short: "Sign this machine out of a resource and forget its credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := credHelper(path)
			if err != nil {
				return err
			}
			ok, err := h.Logout(cmd.Context(), args[0])
			if !ok && err == nil {
				fmt.Fprintf(os.Stderr, "Not signed in to %s.\n", args[0])
			}
			return err
		},
	}

	cred := &cobra.Command{Use: "cred", Short: "Credential helper for resources signed in with \"hankoid login\""}
	get := &cobra.Command{
		Use:   "get URL",
		Short: "Print an Authorization header for URL",
		Long: `get prints "Authorization: Bearer TOKEN" for the resource at URL, refreshing the
token when it is near expiry. When the caller was refused and passes the response on
stdin, the token is refreshed even if it hasn't expired. If the machine isn't signed in,
or was signed out, get exits 1 and says to run "hankoid login URL".`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := credHelper(path)
			if err != nil {
				return err
			}
			tok, err := h.Token(cmd.Context(), args[0], refusedOnStdin())
			if errors.Is(err, credhelper.ErrLoginRequired) {
				fmt.Fprintf(os.Stderr, "hankoid: not signed in to %s; run: hankoid login %s\n", args[0], args[0])
				os.Exit(1)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "hankoid: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Authorization: Bearer %s\n", tok)
			return nil
		},
	}
	for _, c := range []*cobra.Command{login, logout, get} {
		pathFlag(c)
	}
	cred.AddCommand(get)
	root.AddCommand(login, logout, cred)
}

// refusedOnStdin reports whether the caller passed a refused response: per the helper contract
// (hyper9 design 0119), stdin is empty on a first attempt and carries the 401 or 403 response on
// the retry. A terminal is never read, and a pipe left open with nothing in it counts as empty
// after a short wait, so a caller that doesn't close stdin can't hang the helper.
func refusedOnStdin() bool {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return false
	}
	got := make(chan bool, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		got <- len(bytes.TrimSpace(b)) > 0
	}()
	select {
	case refused := <-got:
		return refused
	case <-time.After(250 * time.Millisecond):
		return false
	}
}
