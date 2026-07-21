Output assets/demo.gif
Set FontSize 13
Set Width 1000
Set Height 560
Set Padding 20
Set Theme "Dracula"

Type "redloop --version"
Enter
Sleep 1s

Type "redloop run --preset demo"
Enter
Sleep 4s

Type "head -c 280 demo_hardening.jsonl"
Enter
Sleep 2s

Type "redloop run --n 3 --no-emit"
Enter
Sleep 4s

Sleep 2s
