// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Reflection;
using System.Runtime.Loader;

namespace Nethermind.Crypto;

public static class Pairings
{
    private const string LibraryName = "eth_pairings";

    static Pairings() => AssemblyLoadContext.Default.ResolvingUnmanagedDll += OnResolvingUnmanagedDll;

    [DllImport(LibraryName)]
    private static extern unsafe uint eip196_perform_operation(
        byte operation,
        byte* input,
        int inputLength,
        byte* output,
        ref int outputLength,
        byte* error,
        ref int errorLength);

    [DllImport(LibraryName)]
    private static extern unsafe uint eip2537_perform_operation(
        byte operation,
        byte* input,
        int inputLength,
        byte* output,
        ref int outputLength,
        byte* error,
        ref int errorLength);

    private static unsafe bool Bn254Op(byte operation, ReadOnlySpan<byte> input, Span<byte> output)
    {
        int outputLength = output.Length;
        int errorLength = 256;
        uint externalCallResult;

        Span<byte> error = stackalloc byte[errorLength];
        fixed (byte* inputPtr = &MemoryMarshal.GetReference(input))
        fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
        fixed (byte* errorPtr = &MemoryMarshal.GetReference(error))
        {
            externalCallResult = eip196_perform_operation(
                operation, inputPtr, input.Length, outputPtr, ref outputLength, errorPtr, ref errorLength);
        }

        return externalCallResult == 0;
    }

    private static unsafe bool BlsOp(byte operation, ReadOnlySpan<byte> input, Span<byte> output)
    {
        int outputLength = output.Length;
        int errorLength = 256;
        uint externalCallResult;

        Span<byte> error = stackalloc byte[errorLength];
        fixed (byte* inputPtr = &MemoryMarshal.GetReference(input))
        fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
        fixed (byte* errorPtr = &MemoryMarshal.GetReference(error))
        {
            externalCallResult = eip2537_perform_operation(
                operation, inputPtr, input.Length, outputPtr, ref outputLength, errorPtr, ref errorLength);
        }

        return externalCallResult == 0;
    }

    public static bool Bn254Add(ReadOnlySpan<byte> input, Span<byte> output) => Bn254Op(1, input, output);

    public static bool Bn254Mul(ReadOnlySpan<byte> input, Span<byte> output) => Bn254Op(2, input, output);

    public static bool Bn254Pairing(ReadOnlySpan<byte> input, Span<byte> output) => Bn254Op(3, input, output);

    public static bool BlsG1Add(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(1, input, output);

    public static bool BlsG1Mul(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(2, input, output);

    public static bool BlsG1MultiExp(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(3, input, output);

    public static bool BlsG2Add(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(4, input, output);

    public static bool BlsG2Mul(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(5, input, output);

    public static bool BlsG2MultiExp(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(6, input, output);

    public static bool BlsPairing(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(7, input, output);

    public static bool BlsMapToG1(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(8, input, output);

    public static bool BlsMapToG2(ReadOnlySpan<byte> input, Span<byte> output) => BlsOp(9, input, output);

    private static nint OnResolvingUnmanagedDll(Assembly context, string path)
    {
        if (!path.Equals(LibraryName, StringComparison.OrdinalIgnoreCase))
        {
            return IntPtr.Zero;
        }

        (string? platform, string? extension) =
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? ("linux", "so") :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? ("osx", "dylib") :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ("win", "dll") : default;

        if (platform is null)
        {
            return IntPtr.Zero;
        }

        string? arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null,
        };

        if (arch is null)
        {
            return IntPtr.Zero;
        }

        return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, $"runtimes/{platform}-{arch}/native/{path}.{extension}"));
    }
}
