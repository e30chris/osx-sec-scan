// Package harden defines the macOS security baseline: how to check each item and,
// where it can be scripted, how to apply it. Apply asks before every change.
package harden

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/runner"
)

const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Item is one baseline setting.
type Item struct {
	ID       string
	Name     string
	Critical bool // failing is High severity in scans
	// Check returns whether the item is in the desired state.
	Check func() (ok bool, detail string)
	// Apply commands run as root. Empty means it must be done by hand (see Manual).
	Apply [][]string
	// AsUser runs Apply as the invoking (sudo) user instead of root.
	AsUser bool
	Manual string
}

// Result is the evaluation of one item.
type Result struct {
	Item   Item
	OK     bool
	Detail string
}

func Items() []Item {
	return []Item{
		{
			ID: "sip", Name: "System Integrity Protection", Critical: true,
			Check:  outputMatches(`enabled`, `disabled`, "/usr/bin/csrutil", "status"),
			Manual: "Boot to Recovery (hold power button), open Terminal, run: csrutil enable",
		},
		{
			ID: "filevault", Name: "FileVault disk encryption", Critical: true,
			Check:  outputMatches(`FileVault is On`, ``, "/usr/bin/fdesetup", "status"),
			Manual: "System Settings > Privacy & Security > FileVault > Turn On",
		},
		{
			ID: "gatekeeper", Name: "Gatekeeper", Critical: true,
			Check:  outputMatches(`assessments enabled`, ``, "/usr/sbin/spctl", "--status"),
			Apply:  [][]string{{"/usr/sbin/spctl", "--global-enable"}},
			Manual: "System Settings > Privacy & Security > Allow applications from: App Store & Known Developers",
		},
		{
			ID: "firewall", Name: "Application firewall", Critical: true,
			Check: outputMatches(`enabled`, `disabled`, fw, "--getglobalstate"),
			Apply: [][]string{{fw, "--setglobalstate", "on"}},
		},
		{
			ID: "stealth", Name: "Firewall stealth mode",
			Check: outputMatches(`\b(on|enabled)\b`, `\b(off|disabled)\b`, fw, "--getstealthmode"),
			Apply: [][]string{{fw, "--setstealthmode", "on"}},
		},
		{
			ID: "swu-check", Name: "Automatically check for macOS updates",
			Check: outputMatches(`turned on`, `turned off`, "/usr/sbin/softwareupdate", "--schedule"),
			Apply: [][]string{{"/usr/sbin/softwareupdate", "--schedule", "on"}},
		},
		defaultsBool("swu-download", "Automatically download macOS updates", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload", true),
		defaultsBool("swu-critical", "Install security responses and system files", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall", true),
		defaultsBool("swu-config", "Install XProtect / malware definition updates", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall", true),
		defaultsBool("swu-macos", "Automatically install macOS updates", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates", true),
		defaultsBool("appstore-auto", "Automatically update App Store apps", "/Library/Preferences/com.apple.commerce", "AutoUpdate", true),
		{
			ID: "guest", Name: "Guest account disabled",
			Check: func() (bool, string) {
				v, set := readDefault("/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
				return !set || v == "0", "GuestEnabled=" + v
			},
			Apply: [][]string{{"/usr/bin/defaults", "write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false"}},
		},
		{
			ID: "autologin", Name: "Automatic login disabled", Critical: true,
			Check: func() (bool, string) {
				v, set := readDefault("/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
				return !set, "autoLoginUser=" + v
			},
			Apply: [][]string{{"/usr/bin/defaults", "delete", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"}},
		},
		{
			ID: "screenlock", Name: "Password required immediately after sleep/screensaver",
			Check: outputMatches(`immediate`, `off`, "/usr/sbin/sysadminctl", "-screenLock", "status"),
			Manual: "Needs your login password, so run it yourself (no sudo): sysadminctl -screenLock immediate -password -\n" +
				"Also: System Settings > Lock Screen > start screen saver / turn display off after 5–10 min.",
		},
		{
			ID: "terminal-securekbd", Name: "Terminal Secure Keyboard Entry (blocks other apps reading keystrokes)",
			Check: func() (bool, string) {
				v, _ := readDefaultAsUser("com.apple.Terminal", "SecureKeyboardEntry")
				return v == "1", "SecureKeyboardEntry=" + v
			},
			Apply:  [][]string{{"/usr/bin/defaults", "write", "com.apple.Terminal", "SecureKeyboardEntry", "-bool", "true"}},
			AsUser: true,
			Manual: "Restart Terminal afterward. iTerm2/Ghostty have their own Secure Keyboard Entry menu items.",
		},
		notListening("ssh", "Remote Login (SSH) off", 22,
			[][]string{{"/usr/sbin/systemsetup", "-f", "-setremotelogin", "off"}},
			"System Settings > General > Sharing > Remote Login"),
		notListening("screensharing", "Screen Sharing off", 5900,
			[][]string{{"/bin/launchctl", "disable", "system/com.apple.screensharing"}, {"/bin/launchctl", "bootout", "system/com.apple.screensharing"}},
			"System Settings > General > Sharing > Screen Sharing"),
		notListening("ard", "Remote Management (ARD) off", 3283,
			[][]string{{"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart", "-deactivate", "-configure", "-access", "-off"}},
			"System Settings > General > Sharing > Remote Management"),
		notListening("smb", "File Sharing (SMB) off", 445,
			[][]string{{"/bin/launchctl", "disable", "system/com.apple.smbd"}, {"/bin/launchctl", "bootout", "system/com.apple.smbd"}},
			"System Settings > General > Sharing > File Sharing"),
		{
			ID: "lulu", Name: "LuLu outbound firewall active",
			Check: func() (bool, string) {
				out := runner.Run(30*time.Second, "/usr/bin/systemextensionsctl", "list").Combined()
				for _, l := range strings.Split(out, "\n") {
					if strings.Contains(l, "com.objective-see.lulu") && strings.Contains(l, "[activated enabled]") {
						return true, "network extension activated"
					}
				}
				return false, "LuLu network extension not active"
			},
			Manual: "brew bundle --file Brewfile, open LuLu once and approve its network extension",
		},
		{
			ID: "blockblock", Name: "BlockBlock persistence monitor running",
			Check: func() (bool, string) {
				daemon := "/Library/Objective-See/BlockBlock/BlockBlock.app/Contents/MacOS/BlockBlock"
				helper := "/Applications/BlockBlock Helper.app/"
				var missing []string
				if runner.Run(10*time.Second, "/usr/bin/pgrep", "-f", daemon).ExitCode != 0 {
					missing = append(missing, "daemon not running")
				}
				if runner.Run(10*time.Second, "/usr/bin/pgrep", "-f", helper).ExitCode != 0 {
					missing = append(missing, "helper (alert UI) not running")
				}
				if len(missing) > 0 {
					return false, strings.Join(missing, ", ")
				}
				return true, "daemon and helper running"
			},
			Manual: "Open '/Applications/BlockBlock Helper.app' and make sure it is allowed as a login item (System Settings > General > Login Items)",
		},
		appRunning("reikey", "ReiKey keyboard-tap monitor running", "/Applications/ReiKey.app"),
		appRunning("oversight", "OverSight mic/camera monitor running", "/Applications/OverSight.app"),
	}
}

// Evaluate checks every item without changing anything.
func Evaluate() []Result {
	var out []Result
	for _, it := range Items() {
		ok, d := it.Check()
		out = append(out, Result{Item: it, OK: ok, Detail: d})
	}
	return out
}

// PrintCheck writes a human-readable table of Evaluate results.
func PrintCheck() (failing int) {
	for _, r := range Evaluate() {
		mark := "PASS"
		if !r.OK {
			mark, failing = "FAIL", failing+1
		}
		fmt.Printf("[%s] %-62s %s\n", mark, r.Item.Name, oneLine(r.Detail))
	}
	return failing
}

// Apply walks failing items and, after a y/N confirmation each, runs the fix.
func Apply(assumeYes bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("harden apply changes system settings; run it with sudo")
	}
	in := bufio.NewReader(os.Stdin)
	var manual []string
	for _, r := range Evaluate() {
		if r.OK {
			continue
		}
		it := r.Item
		fmt.Printf("\n[FAIL] %s\n       %s\n", it.Name, oneLine(r.Detail))
		if len(it.Apply) == 0 {
			manual = append(manual, fmt.Sprintf("- %s: %s", it.Name, it.Manual))
			fmt.Println("       manual step (listed at the end)")
			continue
		}
		for _, c := range it.Apply {
			fmt.Printf("       will run: %s%s\n", userPrefix(it.AsUser), strings.Join(c, " "))
		}
		if !assumeYes && !confirm(in, "       apply? [y/N] ") {
			fmt.Println("       skipped")
			continue
		}
		for _, c := range it.Apply {
			if it.AsUser {
				c = asSudoUser(c)
			}
			if err := runner.Interactive(c[0], c[1:]...); err != nil {
				fmt.Printf("       command failed: %v\n", err)
			}
		}
		if ok, d := it.Check(); ok {
			fmt.Println("       now PASS")
		} else {
			fmt.Printf("       still FAIL: %s\n", oneLine(d))
			if it.Manual != "" {
				manual = append(manual, fmt.Sprintf("- %s: %s", it.Name, it.Manual))
			}
		}
		if it.Manual != "" && it.AsUser {
			fmt.Printf("       note: %s\n", it.Manual)
		}
	}
	if len(manual) > 0 {
		fmt.Println("\nManual steps:")
		for _, m := range manual {
			fmt.Println(m)
		}
	}
	return nil
}

func confirm(in *bufio.Reader, prompt string) bool {
	fmt.Print(prompt)
	line, _ := in.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func userPrefix(asUser bool) string {
	if asUser {
		return "(as " + os.Getenv("SUDO_USER") + ") "
	}
	return ""
}

func asSudoUser(c []string) []string {
	u := os.Getenv("SUDO_USER")
	if u == "" {
		return c
	}
	return append([]string{"/usr/bin/sudo", "-u", u}, c...)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// outputMatches passes when good matches and bad (if set) does not.
func outputMatches(good, bad, name string, args ...string) func() (bool, string) {
	g := regexp.MustCompile(good)
	var b *regexp.Regexp
	if bad != "" {
		b = regexp.MustCompile(bad)
	}
	return func() (bool, string) {
		out := strings.TrimSpace(runner.Run(30*time.Second, name, args...).Combined())
		if b != nil && b.MatchString(out) {
			return false, out
		}
		return g.MatchString(out), out
	}
}

func readDefault(domain, key string) (string, bool) {
	r := runner.Run(10*time.Second, "/usr/bin/defaults", "read", domain, key)
	if r.ExitCode != 0 {
		return "unset", false
	}
	return strings.TrimSpace(string(r.Stdout)), true
}

func readDefaultAsUser(domain, key string) (string, bool) {
	if u := os.Getenv("SUDO_USER"); u != "" && os.Geteuid() == 0 {
		r := runner.Run(10*time.Second, "/usr/bin/sudo", "-u", u, "/usr/bin/defaults", "read", domain, key)
		if r.ExitCode != 0 {
			return "unset", false
		}
		return strings.TrimSpace(string(r.Stdout)), true
	}
	return readDefault(domain, key)
}

func defaultsBool(id, name, domain, key string, want bool) Item {
	wantStr, flag := "1", "true"
	if !want {
		wantStr, flag = "0", "false"
	}
	return Item{
		ID: id, Name: name,
		Check: func() (bool, string) {
			v, _ := readDefault(domain, key)
			return v == wantStr, key + "=" + v
		},
		Apply: [][]string{{"/usr/bin/defaults", "write", domain, key, "-bool", flag}},
	}
}

// notListening passes when nothing listens on the TCP port (netstat works without root).
func notListening(id, name string, port int, apply [][]string, manual string) Item {
	re := regexp.MustCompile(fmt.Sprintf(`\.%d\s+\S+\s+LISTEN`, port))
	return Item{
		ID: id, Name: name,
		Check: func() (bool, string) {
			out := runner.Run(30*time.Second, "/usr/sbin/netstat", "-an", "-p", "tcp").Combined()
			if re.MatchString(out) {
				return false, fmt.Sprintf("something is listening on tcp/%d", port)
			}
			return true, fmt.Sprintf("tcp/%d closed", port)
		},
		Apply:  apply,
		Manual: "If it is still on: " + manual,
	}
}

func appRunning(id, name, bundle string) Item {
	return Item{
		ID: id, Name: name,
		Check: func() (bool, string) {
			if _, err := os.Stat(bundle); err != nil {
				return false, bundle + " not installed"
			}
			if runner.Run(10*time.Second, "/usr/bin/pgrep", "-f", bundle+"/").ExitCode != 0 {
				return false, "installed but not running"
			}
			return true, "running"
		},
		Manual: "brew bundle --file Brewfile, then open the app once and approve its system extension / permissions",
	}
}
