using System.Runtime.InteropServices;

namespace JPKIReaderLib
{
	// SCARD_IO_REQUEST structure
	[StructLayout(LayoutKind.Sequential)]
	internal struct SCardIORequest {
		private uint dwProtocol;
		private uint cbPciLength;
		public SCardIORequest(uint protocol, uint pciLength) {
			this.dwProtocol  = protocol;
			this.cbPciLength = pciLength;
		}
	}
}
