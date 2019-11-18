#nullable enable
using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NBitcoin
{

	public interface IBase58Data : IBitcoinString
	{
		Base58Type Type
		{
			get;
		}
	}

	/// <summary>
	/// Base class for all Base58 check representation of data
	/// </summary>
	public abstract class Base58Data : IBase58Data
	{
		protected byte[] vchData = new byte[0];
		protected byte[] vchVersion = new byte[0];
		protected string wifData = "";
		private Network _Network;
		public Network Network
		{
			get
			{
				return _Network;
			}
		}

		protected Base58Data(string base58, Network expectedNetwork)
		{
			if (base58 == null)
				throw new ArgumentNullException(nameof(base58));
			if (expectedNetwork == null)
				throw new ArgumentNullException(nameof(expectedNetwork));
			_Network = expectedNetwork;

			if (_Network.TryExtractBase58Data(Type, base58, out var data) && data is byte[])
			{
				this.vchData = data;
				this.wifData = base58;
			}
			else if (_Network.NetworkStringParser.TryParse(base58, Network, this.GetType(), out var other) && other is Base58Data o)
			{
				this.vchData = o.vchData;
				this.wifData = o.wifData;
			}
			else
			{
				throw new FormatException("Invalid " + this.GetType().Name);
			}

			if (!IsValid)
				throw new FormatException("Invalid " + this.GetType().Name);

		}

		protected Base58Data(byte[] rawBytes, Network network)
		{
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			_Network = network;
			SetData(rawBytes);
		}


		private void SetData(byte[] vchData)
		{
			this.vchData = vchData;
			if (_Network.GetVersionBytes(Type, true) is byte[] v)
			{
				wifData = _Network.NetworkStringParser.GetBase58CheckEncoder().EncodeData(v.Concat(vchData).ToArray());
			}

			if (!IsValid)
				throw new FormatException("Invalid " + this.GetType().Name);
		}


		protected virtual bool IsValid
		{
			get
			{
				return true;
			}
		}

		public abstract Base58Type Type
		{
			get;
		}



		public string ToWif()
		{
			return wifData;
		}
		public byte[] ToBytes()
		{
			return vchData.ToArray();
		}
		public override string ToString()
		{
			return wifData;
		}

		public override bool Equals(object obj)
		{
			if (obj is Base58Data base58Data)
				return Network == base58Data.Network && ToString().Equals(base58Data.ToString());
			return false;
		}
		public static bool operator ==(Base58Data a, Base58Data b)
		{
			if (System.Object.ReferenceEquals(a, b))
				return true;
			if (((object)a == null) || ((object)b == null))
				return false;
			return a.ToString() == b.ToString();
		}

		public static bool operator !=(Base58Data a, Base58Data b)
		{
			return !(a == b);
		}

		public override int GetHashCode()
		{
			return ToString().GetHashCode();
		}
	}
}
#nullable disable
