// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Reflection;

namespace Nethermind.Crypto;

public static class Pairings
{
    private const string LibraryName = "eth_pairings";
    private static string? _libraryFallbackPath;

    static Pairings() => NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), LoadLibrary);

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

    private static nint LoadLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (_libraryFallbackPath is null)
        {
            if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out var handle))
                return handle;
        
            string platform;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                libraryName = $"lib{libraryName}.so";
                platform = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                libraryName = $"lib{libraryName}.dylib";
                platform = "osx";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                libraryName = $"{libraryName}.dll";
                platform = "win";
            }
            else
                throw new PlatformNotSupportedException();

            var arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

            _libraryFallbackPath = Path.Combine("runtimes", $"{platform}-{arch}", "native", libraryName);
        }

        return NativeLibrary.Load(_libraryFallbackPath, assembly, searchPath);
    }
}
