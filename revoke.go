package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"redact-ext-age/ageutil"
)

func cmdRevoke() *cli.Command {
	return command("revoke", "Remove matching age recipient registrations", revokeAction)
}

func revokeAction(_ context.Context, cmd *cli.Command) error {
	settings, err := parseSettings(cmd.Args().Slice(), "recipient", "file")
	if err != nil {
		return err
	}

	if len(settings.values("recipient"))+len(settings.values("file")) == 0 {
		return missing(ErrRevokeRecipientInputRequired)
	}

	selectors, failures := revokeSelectors(settings)

	recipients, scanFailures := readRecipients()
	failures = append(failures, scanFailures...)

	matched := matchingRecipients(recipients, selectors)

	if len(matched) == 0 {
		if len(failures) > 0 {
			return failed(errors.Join(failures...))
		}

		return missing(fmt.Errorf("no registered age recipient matches %q", selectors))
	}

	removed, removeFailures := removeRecipients(matched)
	failures = append(failures, removeFailures...)

	fmt.Fprintf(os.Stderr,
		"Removed %d age recipient registration%s. Commit and push repository changes to distribute revocation.\n",
		removed, map[bool]string{true: "", false: "s"}[removed == 1],
	)

	if len(failures) > 0 {
		return failed(errors.Join(failures...))
	}

	return nil
}

func revokeSelectors(settings settings) ([]string, []error) {
	var failures []error

	selectors := make([]string, 0)

	for _, selector := range settings.values("recipient") {
		parsed, err := ageutil.ParseRecipient(selector)
		if err != nil {
			failures = append(failures, fmt.Errorf("parsing age recipient %q: %w", selector, err))
			fmt.Fprintf(os.Stderr, "Unable to parse recipient %q: %v\n", selector, err)

			continue
		}

		text, err := ageutil.RecipientText(parsed)
		if err != nil {
			failures = append(failures, fmt.Errorf("identifying age recipient %q: %w", selector, err))
			fmt.Fprintf(os.Stderr, "Unable to identify recipient %q: %v\n", selector, err)

			continue
		}

		selectors = append(selectors, text)
	}

	for _, filename := range settings.values("file") {
		parsed, err := ageutil.ParseRecipientsFile(filename)
		if err != nil {
			failures = append(failures, fmt.Errorf("loading recipient file %q: %w", filename, err))
			fmt.Fprintf(os.Stderr, "Unable to load recipient file %q: %v\n", filename, err)

			continue
		}

		for _, key := range parsed {
			text, err := ageutil.RecipientText(key)
			if err != nil {
				failures = append(failures, fmt.Errorf("identifying recipient from file %q: %w", filename, err))
				fmt.Fprintf(os.Stderr, "Unable to identify recipient from file %q: %v\n", filename, err)

				continue
			}

			selectors = append(selectors, text)
		}
	}

	return selectors, failures
}

func removeRecipients(recipients []recipient) (int, []error) {
	removed := 0

	var failures []error

	for _, item := range recipients {
		// An encrypted collection is the registration of its recipient, so
		// removing it is the revocation. A registration file an earlier layout
		// left behind goes with it.
		if err := removeIfPresent(item.filename); err != nil {
			failures = append(failures, fmt.Errorf("removing encrypted recipient copy %s: %w", item.filename, err))
			fmt.Fprintf(os.Stderr, "Unable to remove encrypted copy for %s: %v\n", item.text, err)

			continue
		}

		stale := strings.TrimSuffix(item.filename, ExtAgeSecret) + ExtAgePubKey
		if err := removeIfPresent(stale); err != nil {
			failures = append(failures, fmt.Errorf("removing recipient registration %s: %w", stale, err))
			fmt.Fprintf(os.Stderr, "Unable to remove registration for %s: %v\n", item.text, err)

			continue
		}

		removed++
	}

	return removed, failures
}

func removeIfPresent(filename string) error {
	err := os.Remove(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return err
}
