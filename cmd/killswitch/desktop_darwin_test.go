package main

import "testing"

func TestInAppBundleOnlyInsideContentsMacOS(t *testing.T) {
	eq(t, inAppBundle("/Applications/killswitch.app/Contents/MacOS/killswitch"), true)
	eq(t, inAppBundle("/usr/local/bin/killswitch"), false)
	eq(t, inAppBundle("/tmp/Contents/MacOS/killswitch"), false)
	eq(t, inAppBundle("/tmp/x.app/Contents/Resources/killswitch"), false)
	eq(t, inAppBundle("/tmp/x.app/Other/MacOS/killswitch"), false)
}
