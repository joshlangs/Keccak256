using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Epoche
{
    public static class Keccak256
    {
        static readonly BouncyKeccak256 Hasher = new BouncyKeccak256();

        static string Hex(IEnumerable<byte> data, bool prefix0x)
        {
            var hex = string.Concat(data.Select(x => x.ToString("x2")));
            return prefix0x ? "0x" + hex : hex;
        }

        public static byte[] ComputeHash(byte[] input)
        {
            if (Monitor.TryEnter(Hasher))
            {
                try
                {
                    return ComputeHash(Hasher, input, true);
                }
                finally
                {
                    Monitor.Exit(Hasher);
                }
            }
            return ComputeHash(new BouncyKeccak256(), input, false);
        }
        public static byte[] ComputeHash(string input) => ComputeHash(Encoding.UTF8.GetBytes(input));

        public static string ComputeHashString(byte[] input, bool prefix0x) => Hex(ComputeHash(input), prefix0x);
        public static string ComputeHashString(string input, bool prefix0x) => ComputeHashString(Encoding.UTF8.GetBytes(input), prefix0x);


        public static async Task<byte[]> ComputeHashAsync(Stream input, CancellationToken cancellationToken = default)
        {
            var hasher = new BouncyKeccak256();
            var buffer = new byte[8192];
            while (true)
            {
                var r = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                if (r == 0)
                {
                    var hash = new byte[32];
                    hasher.DoFinal(hash, 0);
                    return hash;
                }
                hasher.BlockUpdate(buffer, 0, r);
            }
        }
        public static async Task<string> ComputeHashStringAsync(Stream input, bool prefix0x, CancellationToken cancellationToken = default) => Hex(await ComputeHashAsync(input, cancellationToken), prefix0x);

        static byte[] ComputeHash(BouncyKeccak256 hasher, byte[] input, bool reset)
        {
            if (reset)
            {
                hasher.Reset();
            }
            hasher.BlockUpdate(input, 0, input.Length);
            var hash = new byte[32];
            hasher.DoFinal(hash, 0);
            return hash;
        }

        public static string ComputeEthereumFunctionSelector(string functionSignature, bool prefix0x = true) => Hex(ComputeHash(functionSignature).Take(4), prefix0x);
    }
}
