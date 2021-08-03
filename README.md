# Anti10016
This is a powershell script to attempt fix DCOM 10016 errors.

It is quite a common issue, when you for some reason go to event viewer and see lots of events with ID 10016. While Microsoft suggests ignoring them, treating them as "no issue", they, at least, can clog up the logs, which is not good. Common solution for that is this [one](https://answers.microsoft.com/en-us/windows/forum/windows_8-performance/event-id-10016-the-application-specific-permission/9ff8796f-c352-4da2-9322-5fdf8a11c81e). Obviously it's manual.  
The scripts commonly found as promoted fixes are gists from [kitmenke](https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4) and [Parahexen](https://gist.github.com/Parahexen/c8a2e8d553eb3ac5d15d0a2e0687f05e), but they are far from perfect. kitmenke's solution, in the end, only covers taking ownership and Parahexen uses HKCR hive, which may provide unexpected results when setting values in it as mentioned [here](https://stackoverflow.com/questions/53984433/hkey-local-machine-software-classes-vs-hkey-classes-root) (and also can have quite a lot of potentially unneeded output, including errors, that are not exactly errors).  

And here comes this script. It's based on the work done by the others, but has some distinctions:
1. Uses HKLM and HKCU hives instead of HKCR hive
2. Grants access to DCOM not only to all SIDs mentioned in the error (it looks like 2 values can be provided) plus SYSTEM, LOCAL SERVICE and Built-In Administrators Group
3. It does validate the expected SID values, that they are SIDs
4. In case AppID path is missing LaunchPermissions value, it will be created
5. All events are parsed, but there is a "tracking" logic, that will avoid processing same even twice (or more), which can improve performance
6. Some other changes to potentially improve performance (enabling privileges outside of the function does seem to result in errors on following iterrations, so no improvement there)
7. Cleaner (and color-coded) output

If you have this issue - download the file and run it in PowerShell.
