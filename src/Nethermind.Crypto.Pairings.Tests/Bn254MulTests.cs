// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

namespace Nethermind.Crypto.Tests;

public class Bn254MulTests
{
    [Theory]
    [MemberData(nameof(Cases))]
    public void Should_return_valid_result(byte[] input, byte[] expected)
    {
        Span<byte> output = stackalloc byte[64];

        var success = Pairings.Bn254Mul(input.AsSpan(), output);

        Assert.True(success);
        Assert.Equivalent(expected, output.ToArray(), true);
    }

    public static TheoryData<byte[], byte[]> Cases => new()
    {
        { Convert.FromHexString("089142debb13c461f61523586a60732d8b69c5b38a3380a74da7b2961d867dbf2d5fc7bbc013c16d7945f190b232eacc25da675c0eb093fe6b9f1b4b4e107b36ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("0bf982b98a2757878c051bfe7eee228b12bc69274b918f08d9fcb21e9184ddc10b17c77cbf3c19d5d27e18cbd4a8c336afb488d0e92c18d56e64dd4ea5c437e6") },
        { Convert.FromHexString("25f8c89ea3437f44f8fc8b6bfbb6312074dc6f983809a5e809ff4e1d076dd5850b38c7ced6e4daef9c4347f370d6d8b58f4b1d8dc61a3c59d651a0644a2a27cfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("18a902ac147b2951531770c7c18a25e3dd87765e23f7e0c4e9d62b624a6e37450288473776e7e99b2aaa27e8f4656ea9ce5e634fd1ca1aab45315199ecaced2e") },
        { Convert.FromHexString("23f16f1bcc31bd002746da6fa3825209af9a356ccd99cf79604a430dd592bcd90a03caeda9c5aa40cdc9e4166e083492885dad36c72714e3697e34a4bc72ccaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("0c6a880ffdd0737c53bfec9b65c9098a3298747bd4e5fd07026661b4cb804331116aeec88e11f49753df224c60c4bd8b8bc0a98b8d50f24ce64475268d227f4c") },
        { Convert.FromHexString("21315394462f1a39f87462dbceb92718b220e4f80af516f727ad85380fadefbc2e4f40ea7bbe2d4d71f13c84fd2ae24a4a24d9638dd78349d0dee8435a67cca6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("1d7985d51e53cdfbd73b051e9a74ab6e621b6b664a7efed00e30c1264f5623d02808eee3baec187160d2499b4aedbc665a532d245212a1be61e0d4b9b36f3075") },
        { Convert.FromHexString("0341b65d1b32805aedf29c4704ae125b98bb9b736d6e05bd934320632bf46bb60d22bc985718acbcf51e3740c1565f66ff890dfd2302fc51abc999c83d8774baffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("15bd6ea71fd264e1bfb04eb6d97b4f3686c5bf36f91356fc13ddde3494e172d90b3f8392fd4cdd5d542887ea4ee0274835bf37b58edf927ef242b8704af52e92") },
        { Convert.FromHexString("08ed1b33fe3cd3b1ac11571999e8f451f5bb28dd4019e58b8d24d91cf73dc38f11be2878bb118612a7627f022aa19a17b6eb599bba4185df357f81d052fff90bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("26ec73a6134f8ebce33d675e1f2e6ff3ec066e8d255ffca6eb55ef2ab7c5c51d06500cfcd6950c92de24b90ca09be110f8f9c2fb4d9cb2a9f9677dd81c1c0607") },
        { Convert.FromHexString("279e2a1eee50ae1e3fe441dcd58475c40992735644de5c8f6299b6f0c1fe41af21b37bd13a881181d56752e31cf494003a9d396eb908452718469bc5c75aa807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("06894837c70570eac651dae1a443b830c292c1801340ca4150c9d339177965e509ad8d4839bc83bd1852e6a8b71dcf01a1f7d6b6b174858ca02893bd5ace3eee") },
        { Convert.FromHexString("1c35e297f7c55363cd2fd00d916c67fad3bdea15487bdc5cc7b720f3a2c8b776106c2a4cf61ab73f91f2258f1846b9be9d28b9a7e83503fa4f4b322bfc07223cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("0e56eeb3f168767b21bce1489d9657f694951b25ea8a081f4ebf68469a1eb1e0293446d763ea9c40e52286f2ac504cfabb364b1f899b874b13d78879d25a5ec5") },
        { Convert.FromHexString("0af6f1fd0b29a4f055c91a472f285e919d430a2b73912ae659224e24a458c65e2c1a52f5abf3e86410b9a603159b0bf51abf4d72cbd5e8161a7b5c47d60dfe57ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("2f63f5f1275c401356e94adfbe5e8cff21485a9281e55d378a51eb93263a40802a817491a84e40c584481df4a5085b301c6fd66cb97856de55cd04df85a6a1d3") },
        { Convert.FromHexString("1f752f85cf5cc01b2dfe279541032da61c2fcc8ae0dfc6d4253ba9b5d3c858231d03a84afe2a9f595ab03007400ccd36a2c0bc31203d881011dfc450c39b5abeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Convert.FromHexString("0aa7b6fda656f23eab50e36db0519cdf79f4624d417253085907ebfd9aef38a414cdd2edce2b313fc6dd390628ac9fac910841706d55f9af2a064548694dc05c") }
    };
}
