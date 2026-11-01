using System.Text;
using Xunit;

namespace Epoche.Keccak256Tests;

public class Keccak256Tests
{
    [Theory]
    [InlineData("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")]
    [InlineData("depositBNB()", "42220f3419be466f213f4b3042de8080f1629750f4ad2a978c9aac1c4d15ec51")]
    [InlineData("depositAll()", "de5f62680220b9bac30b82cd3c6046aab77423e742dda8ca78b10a1921b1f21b")]
    [InlineData("transfer(address,uint256)", "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b")]
    public async Task TestCases(string input, string expected)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal(expected, ToLowerHex(Keccak256.ComputeHash(input)));
        Assert.Equal(expected, Keccak256.ComputeHashString(input, false));
        Assert.Equal("0x" + expected, Keccak256.ComputeHashString(input, true));
        Assert.Equal(expected, ToLowerHex(Keccak256.ComputeHash(bytes)));
        Assert.Equal(expected, Keccak256.ComputeHashString(bytes, false));
        Assert.Equal("0x" + expected, Keccak256.ComputeHashString(bytes, true));
        Assert.Equal(expected,
            ToLowerHex(await Keccak256.ComputeHashAsync(new MemoryStream(bytes), cancellationToken)));
        Assert.Equal(expected,
            await Keccak256.ComputeHashStringAsync(new MemoryStream(bytes), false, cancellationToken));
        Assert.Equal("0x" + expected,
            await Keccak256.ComputeHashStringAsync(new MemoryStream(bytes), true, cancellationToken));
        Assert.Equal("0x" + expected[..8], Keccak256.ComputeEthereumFunctionSelector(input));
        Assert.Equal("0x" + expected[..8], Keccak256.ComputeEthereumFunctionSelector(input, true));
        Assert.Equal(expected[..8], Keccak256.ComputeEthereumFunctionSelector(input, false));
    }

    static string ToLowerHex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    [Fact]
    public async Task Test1MBZero()
    {
        const string expected = "7b6ff0a03e9c5a8e77a2059bf28e26a7f0e8d3939a7cfe2193908ad8d683be90";
        var bytes = new byte[1024 * 1024];
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal(expected, ToLowerHex(Keccak256.ComputeHash(bytes)));
        Assert.Equal(expected, Keccak256.ComputeHashString(bytes, false));
        Assert.Equal("0x" + expected, Keccak256.ComputeHashString(bytes, true));
        Assert.Equal(expected,
            ToLowerHex(await Keccak256.ComputeHashAsync(new MemoryStream(bytes), cancellationToken)));
        Assert.Equal(expected,
            await Keccak256.ComputeHashStringAsync(new MemoryStream(bytes), false, cancellationToken));
        Assert.Equal("0x" + expected,
            await Keccak256.ComputeHashStringAsync(new MemoryStream(bytes), true, cancellationToken));
    }

    [Fact]
    public void Test1MBZero_blocks()
    {
        var hasher = new BouncyKeccak256();

        var bytes = new byte[136];
        var count = 0;
        while (count < 1024 * 1024)
        {
            for (var i = 1; i <= bytes.Length; i++)
            {
                var left = 1024 * 1024 - count;
                if (i > left)
                {
                    continue;
                }

                hasher.BlockUpdate(bytes, 0, i);
                count += i;
            }
        }

        var hash = new byte[32];
        var final = hasher.DoFinal(hash, 0);
        Assert.Equal(32, final);

        const string expected = "7b6ff0a03e9c5a8e77a2059bf28e26a7f0e8d3939a7cfe2193908ad8d683be90";
        var actual = string.Concat(hash.Select(x => x.ToString("x2")));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void RunMultiThread()
    {
        const string expected = "7b6ff0a03e9c5a8e77a2059bf28e26a7f0e8d3939a7cfe2193908ad8d683be90";
        var bytes = new byte[1024 * 1024];

        Enumerable
            .Repeat(0, 10)
            .AsParallel()
            .Select(_ => ComputeAsync(bytes, expected))
            .ToArray();
    }

    static string ComputeAsync(byte[] bytes, string expected)
    {
        var end = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < end)
        {
            var current = ToLowerHex(Keccak256.ComputeHash(bytes));
            if (expected != current)
            {
                throw new Exception($"Can't properly calculate in multi thread mode ({expected} vs {current})");
            }
        }

        return string.Empty;
    }
}
