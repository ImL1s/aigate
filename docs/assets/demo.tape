# VHS tape script for aigate demo GIF
# Install VHS: brew install charmbracelet/tap/vhs
# Record: vhs docs/assets/demo.tape

Output docs/assets/demo.gif

Set Shell "zsh"
Set FontSize 16
Set Width 900
Set Height 500
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms

# Title
Type "# aigate — AI-powered supply chain security"
Enter
Sleep 1s

# Check a safe package
Type "aigate check requests --skip-ai"
Enter
Sleep 3s

# Check a known typosquat
Type "aigate check crossenv --skip-ai"
Enter
Sleep 3s

# Check credential theft pattern
Type "aigate check ctx -v 0.2.6 --skip-ai"
Enter
Sleep 3s

# Show doctor
Type "aigate doctor"
Enter
Sleep 3s

# Done
Sleep 2s
