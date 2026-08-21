using System.Numerics;
using System.Security.Cryptography;

namespace ReproIt.Sdk;

/// <summary>Implements RFC 8032 Ed25519 for managed capture attestations.</summary>
/// <remarks>
/// .NET 8 does not ship Ed25519 in the base class library, so this class
/// implements the signature scheme directly over <see cref="BigInteger"/>
/// field arithmetic. Every input is bounded and every invalid encoding is
/// rejected before use. The cross-language conformance vectors pin this
/// implementation byte for byte against the Rust reference signer.
/// </remarks>
internal static class ManagedEd25519
{
    internal const int SeedBytes = 32;
    internal const int PublicKeyBytes = 32;
    internal const int SignatureBytes = 64;

    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger L = BigInteger.Pow(2, 252) +
        BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D = BigInteger.Parse(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555");
    private static readonly BigInteger SqrtMinusOne =
        BigInteger.ModPow(2, (P - 1) / 4, P);
    private static readonly Point BasePoint = new(
        BigInteger.Parse(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        BigInteger.Parse(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960"),
        BigInteger.One,
        Mod(BigInteger.Parse(
                "15112221349535400772501151409588531511454012693041857206046113283949847762202") *
            BigInteger.Parse(
                "46316835694926478169428394003475163141307993866256225615783033603165251855960")));

    /// <summary>One curve point in extended homogeneous coordinates.</summary>
    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    /// <summary>Derives the 32-byte public key from a 32-byte seed.</summary>
    internal static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedBytes)
        {
            throw new ArgumentException("The Ed25519 seed must contain 32 bytes.", nameof(seed));
        }
        byte[] digest = SHA512.HashData(seed);
        BigInteger scalar = ClampScalar(digest.AsSpan(0, 32));
        return Encode(Multiply(scalar, BasePoint));
    }

    /// <summary>Signs a message with a 32-byte seed, returning 64 signature bytes.</summary>
    internal static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedBytes)
        {
            throw new ArgumentException("The Ed25519 seed must contain 32 bytes.", nameof(seed));
        }
        byte[] digest = SHA512.HashData(seed);
        BigInteger secretScalar = ClampScalar(digest.AsSpan(0, 32));
        byte[] publicKey = Encode(Multiply(secretScalar, BasePoint));
        BigInteger nonce = HashToScalar(digest.AsSpan(32, 32), default, message);
        byte[] commitment = Encode(Multiply(nonce, BasePoint));
        BigInteger challenge = HashToScalar(commitment, publicKey, message);
        BigInteger response = Mod(nonce + challenge * secretScalar, L);
        byte[] signature = new byte[SignatureBytes];
        commitment.CopyTo(signature, 0);
        EncodeScalar(response).CopyTo(signature, 32);
        return signature;
    }

    /// <summary>Reports whether a 64-byte signature verifies for a message.</summary>
    internal static bool Verify(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureBytes || publicKey.Length != PublicKeyBytes)
        {
            return false;
        }
        if (!TryDecode(signature[..32], out Point commitment) ||
            !TryDecode(publicKey, out Point point))
        {
            return false;
        }
        BigInteger response = DecodeScalar(signature[32..]);
        if (response >= L)
        {
            return false;
        }
        BigInteger challenge = HashToScalar(
            signature[..32].ToArray(), publicKey.ToArray(), message);
        Point left = Multiply(response, BasePoint);
        Point right = Add(commitment, Multiply(challenge, point));
        return Encode(left).AsSpan().SequenceEqual(Encode(right));
    }

    private static BigInteger ClampScalar(ReadOnlySpan<byte> value)
    {
        byte[] clamped = value.ToArray();
        clamped[0] &= 0xF8;
        clamped[31] &= 0x7F;
        clamped[31] |= 0x40;
        return DecodeScalar(clamped);
    }

    private static BigInteger HashToScalar(
        ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> message)
    {
        byte[] joined = new byte[first.Length + second.Length + message.Length];
        first.CopyTo(joined);
        second.CopyTo(joined.AsSpan(first.Length));
        message.CopyTo(joined.AsSpan(first.Length + second.Length));
        return Mod(DecodeScalar(SHA512.HashData(joined)), L);
    }

    private static Point Add(Point left, Point right)
    {
        BigInteger a = Mod((left.Y - left.X) * (right.Y - right.X));
        BigInteger b = Mod((left.Y + left.X) * (right.Y + right.X));
        BigInteger c = Mod(left.T * 2 * D % P * right.T);
        BigInteger d = Mod(left.Z * 2 * right.Z);
        BigInteger e = Mod(b - a);
        BigInteger f = Mod(d - c);
        BigInteger g = Mod(d + c);
        BigInteger h = Mod(b + a);
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Double(Point point)
    {
        BigInteger a = Mod(point.X * point.X);
        BigInteger b = Mod(point.Y * point.Y);
        BigInteger c = Mod(2 * point.Z * point.Z);
        BigInteger h = Mod(a + b);
        BigInteger e = Mod(h - (point.X + point.Y) * (point.X + point.Y));
        BigInteger g = Mod(a - b);
        BigInteger f = Mod(c + g);
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Multiply(BigInteger scalar, Point point)
    {
        // The scalar is already reduced below 2^256, so this loop is bounded.
        Point result = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        Point addend = point;
        BigInteger remaining = Mod(scalar, L);
        while (remaining > 0)
        {
            if (!remaining.IsEven)
            {
                result = Add(result, addend);
            }
            addend = Double(addend);
            remaining >>= 1;
        }
        return result;
    }

    private static byte[] Encode(Point point)
    {
        BigInteger inverse = BigInteger.ModPow(point.Z, P - 2, P);
        BigInteger x = Mod(point.X * inverse);
        BigInteger y = Mod(point.Y * inverse);
        byte[] encoded = EncodeScalar(y);
        if (!x.IsEven)
        {
            encoded[31] |= 0x80;
        }
        return encoded;
    }

    private static bool TryDecode(ReadOnlySpan<byte> encoded, out Point point)
    {
        point = default;
        byte[] value = encoded.ToArray();
        int sign = (value[31] & 0x80) >> 7;
        value[31] &= 0x7F;
        BigInteger y = DecodeScalar(value);
        if (y >= P)
        {
            return false;
        }
        BigInteger ySquared = Mod(y * y);
        BigInteger numerator = Mod(ySquared - 1);
        BigInteger denominator = Mod(D * ySquared + 1);
        BigInteger xSquared = Mod(numerator * BigInteger.ModPow(denominator, P - 2, P));
        BigInteger x = BigInteger.ModPow(xSquared, (P + 3) / 8, P);
        if (Mod(x * x) != xSquared)
        {
            x = Mod(x * SqrtMinusOne);
        }
        if (Mod(x * x) != xSquared)
        {
            return false;
        }
        if (x.IsZero && sign == 1)
        {
            return false;
        }
        if ((x.IsEven ? 0 : 1) != sign)
        {
            x = Mod(-x);
        }
        point = new Point(x, y, BigInteger.One, Mod(x * y));
        return true;
    }

    private static BigInteger DecodeScalar(ReadOnlySpan<byte> value) =>
        new(value, isUnsigned: true, isBigEndian: false);

    private static byte[] EncodeScalar(BigInteger value)
    {
        byte[] encoded = new byte[32];
        value.TryWriteBytes(encoded, out _, isUnsigned: true, isBigEndian: false);
        return encoded;
    }

    private static BigInteger Mod(BigInteger value) => Mod(value, P);

    private static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        BigInteger result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }
}
