using System;

namespace JPKIReaderLib
{
    static public class ChangeEndian
    {
        public static char Reverse(char value) => (char)Reverse((ushort)value);
        public static short Reverse(short value) => (short)Reverse((ushort)value);
        public static int Reverse(int value) => (int)Reverse((uint)value);
        public static long Reverse(long value) => (long)Reverse((ulong)value);

        public static ushort Reverse(ushort value)
        {
            return (ushort)((value & 0xFF) << 8 | (value >> 8) & 0xFF);
        }

        public static uint Reverse(uint value)
        {
            return (value & 0xFF) << 24 |
                    ((value >> 8) & 0xFF) << 16 |
                    ((value >> 16) & 0xFF) << 8 |
                    ((value >> 24) & 0xFF);
        }

        public static ulong Reverse(ulong value)
        {
            return (value & 0xFF) << 56 |
                    ((value >> 8) & 0xFF) << 48 |
                    ((value >> 16) & 0xFF) << 40 |
                    ((value >> 24) & 0xFF) << 32 |
                    ((value >> 32) & 0xFF) << 24 |
                    ((value >> 40) & 0xFF) << 16 |
                    ((value >> 48) & 0xFF) << 8 |
                    ((value >> 56) & 0xFF);
        }

        public static float Reverse(float value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            Array.Reverse(bytes);
            return BitConverter.ToSingle(bytes, 0);
        }

        public static double Reverse(double value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            Array.Reverse(bytes);
            return BitConverter.ToDouble(bytes, 0);
        }
    }
}
