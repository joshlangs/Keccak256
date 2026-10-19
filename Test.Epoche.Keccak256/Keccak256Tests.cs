namespace Epoche;

using System.Text;
using Epoche.Shared;

public class Keccak256Tests
{
    [Test]
    [Arguments("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")]
    [Arguments("depositBNB()", "42220f3419be466f213f4b3042de8080f1629750f4ad2a978c9aac1c4d15ec51")]
    [Arguments("depositAll()", "de5f62680220b9bac30b82cd3c6046aab77423e742dda8ca78b10a1921b1f21b")]
    [Arguments("transfer(address,uint256)", "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b")]
    public async Task TestCases(string input, string expected)
    {
        await Assert.That(Keccak256.ComputeHash(input).ToLowerHex()).IsEqualTo(expected);
        await Assert.That(Keccak256.ComputeHashString(input, false)).IsEqualTo(expected);
        await Assert.That(Keccak256.ComputeHashString(input, true)).IsEqualTo("0x" + expected);
        await Assert.That(Keccak256.ComputeHash(Encoding.UTF8.GetBytes(input)).ToLowerHex()).IsEqualTo(expected);
        await Assert.That(Keccak256.ComputeHashString(Encoding.UTF8.GetBytes(input), false)).IsEqualTo(expected);
        await Assert.That(Keccak256.ComputeHashString(Encoding.UTF8.GetBytes(input), true)).IsEqualTo("0x" + expected);
        await Assert.That((await Keccak256.ComputeHashAsync(new MemoryStream(Encoding.UTF8.GetBytes(input)))).ToLowerHex()).IsEqualTo(expected);
        await Assert.That(await Keccak256.ComputeHashStringAsync(new MemoryStream(Encoding.UTF8.GetBytes(input)), false)).IsEqualTo(expected);
        await Assert.That(await Keccak256.ComputeHashStringAsync(new MemoryStream(Encoding.UTF8.GetBytes(input)), true)).IsEqualTo("0x" + expected);
        await Assert.That(Keccak256.ComputeEthereumFunctionSelector(input)).IsEqualTo("0x" + expected[..8]);
        await Assert.That(Keccak256.ComputeEthereumFunctionSelector(input, true)).IsEqualTo("0x" + expected[..8]);
        await Assert.That(Keccak256.ComputeEthereumFunctionSelector(input, false)).IsEqualTo(expected[..8]);
    }
}
