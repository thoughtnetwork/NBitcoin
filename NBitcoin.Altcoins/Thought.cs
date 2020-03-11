using NBitcoin.Altcoins.Cuckoo;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/thoughtnetwork/thought/blob/master/src/chainparams.cpp
	public class Thought : NetworkSetBase
	{
		public static Thought Instance { get; } = new Thought();

		public override string CryptoCode => "THT";

		private Thought()
		{

		}

		public class ThoughtConsensusFactory : ConsensusFactory
		{
			private ThoughtConsensusFactory()
			{
			}

			// ReSharper disable once MemberHidesStaticFromOuterClass
			public static ThoughtConsensusFactory Instance { get; } = new ThoughtConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new ThoughtBlockHeader();
			}

			public override Block CreateBlock()
			{
				return new ThoughtBlock(new ThoughtBlockHeader());
			}

			public override Transaction CreateTransaction()
			{
				return new ThoughtTransaction();
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class ThoughtBlockHeader : BlockHeader
		{
			public const uint CUCKOO_HARDFORK_VERSION_MASK = 0x40000000;
			public const uint CUCKOO_HARDFORK_MIN_TIME = 1528835939;

			private readonly uint[] cuckooProof = new uint[CuckooVerifier.ProofSize];
			public IEnumerable<uint> CuckooProof
			{
				get
				{
					return new List<uint>(cuckooProof);
				}
				set
				{
					int i = 0;
					foreach (var nonce in value)
					{
						if (i == CuckooVerifier.ProofSize)
						{
							throw new ArgumentException("Proof too long");
						}
						cuckooProof[i] = nonce;
						i += 1;
					}
					if (i < CuckooVerifier.ProofSize)
					{
						throw new ArgumentException("Proof too short");
					}
				}
			}

			public override void ReadWrite(BitcoinStream stream)
			{
				base.ReadWrite(stream);
				if (IsCuckooPoW())
				{
					for (var i = 0; i < CuckooVerifier.ProofSize; i++)
					{
						stream.ReadWrite(ref cuckooProof[i]);
					}
				}
			}

			public bool IsCuckooPoW()
			{
				return ((nVersion & CUCKOO_HARDFORK_VERSION_MASK) != 0) && (nTime > CUCKOO_HARDFORK_MIN_TIME);
			}

			public override uint256 GetPoWHash()
			{
				if (IsCuckooPoW())
				{
					var hash = SHA256.Create();
					using (var cryptoStream = new CryptoStream(Stream.Null, hash, CryptoStreamMode.Write))
					{
						foreach (var nonce in cuckooProof)
						{
							cryptoStream.Write(Utils.ToBytes(nonce, true));
						}
					}
					return new uint256(hash.Hash);
				}
				else
				{
					return GetHash();
				}
			}

			protected internal override void SetNull()
			{
				base.SetNull();
				Array.Fill(cuckooProof, 0U);
			}

			internal bool ValidateCuckooProof()
			{
				return CuckooVerifier.Verify(cuckooProof, new SiphashKeys((this).ToBytes()), 24) == VerificationResult.Ok;
			}

			public new bool CheckProofOfWork()
			{
				return (!IsCuckooPoW() || ValidateCuckooProof()) && base.CheckProofOfWork();
			}
		}

		/// <summary>
		/// Transactions with version >= 3 have a special transaction type in the version code
		/// https://docs.thought.org/en/stable/merchants/technical.html#v0-13-0-integration-notes
		/// 0.14 will add more types: https://github.com/thoughtnetwork/dips/blob/master/dip-0002-special-transactions.md
		/// </summary>
		public enum ThoughtTransactionType
		{
			StandardTransaction = 0,
			MasternodeRegistration = 1,
			UpdateMasternodeService = 2,
			UpdateMasternodeOperator = 3,
			MasternodeRevocation = 4,
			MasternodeListMerkleProof = 5,
			QuorumCommitment = 6
		}

		public abstract class SpecialTransaction
		{
			protected SpecialTransaction(byte[] extraPayload)
			{
				data = new BinaryReader(new MemoryStream(extraPayload));
				Version = data.ReadUInt16();
			}

			protected readonly BinaryReader data;
			/// <summary>
			/// Version number. Currently set to 1 for all ThoughtTransactionTypes
			/// </summary>
			public ushort Version { get; set; }

			/// <summary>
			/// https://github.com/thoughtevo/thoughtcore-lib/blob/master/lib/constants/index.js
			/// </summary>
			public const int PUBKEY_ID_SIZE = 20;
			public const int COMPACT_SIGNATURE_SIZE = 65;
			public const int SHA256_HASH_SIZE = 32;
			public const int BLS_PUBLIC_KEY_SIZE = 48;
			public const int BLS_SIGNATURE_SIZE = 96;
			public const int IpAddressLength = 16;

			protected void MakeSureWeAreAtEndOfPayload()
			{
				if (data.BaseStream.Position < data.BaseStream.Length)
					throw new Exception(
						"Failed to parse payload: raw payload is bigger than expected (pos=" +
						data.BaseStream.Position + ", len=" + data.BaseStream.Length + ")");
			}
		}

		/// <summary>
		/// https://github.com/thoughtnetwork/dips/blob/master/dip-0003.md
		/// </summary>
		public class ProviderRegistrationTransaction : SpecialTransaction
		{
			public ProviderRegistrationTransaction(byte[] extraPayload) : base(extraPayload)
			{
				Type = data.ReadUInt16();
				Mode = data.ReadUInt16();
				CollateralHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				CollateralIndex = data.ReadUInt32();
				IpAddress = data.ReadBytes(IpAddressLength);
				Port = BitConverter.ToUInt16(data.ReadBytes(2).Reverse().ToArray(), 0);
				KeyIdOwner = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				KeyIdOperator = data.ReadBytes(BLS_PUBLIC_KEY_SIZE);
				KeyIdVoting = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				OperatorReward = data.ReadUInt16();
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptPayoutSize);
				ScriptPayout = new Script(data.ReadBytes((int)ScriptPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				bs.ReadWriteAsVarInt(ref PayloadSigSize);
				PayloadSig = data.ReadBytes((int)PayloadSigSize);
				MakeSureWeAreAtEndOfPayload();
			}

			public ushort Type { get; set; }
			public ushort Mode { get; set; }
			public uint256 CollateralHash { get; set; }
			public uint CollateralIndex { get; set; }
			public byte[] IpAddress { get; set; }
			public ushort Port { get; set; }
			public uint160 KeyIdOwner { get; set; }
			public byte[] KeyIdOperator { get; set; }
			public uint160 KeyIdVoting { get; set; }
			public ushort OperatorReward { get; set; }
			public uint ScriptPayoutSize;
			public Script ScriptPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateServiceTransaction : SpecialTransaction
		{
			public ProviderUpdateServiceTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				IpAddress = data.ReadBytes(IpAddressLength);
				Port = BitConverter.ToUInt16(data.ReadBytes(2).Reverse().ToArray(), 0);
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptOperatorPayoutSize);
				ScriptOperatorPayout = new Script(data.ReadBytes((int)ScriptOperatorPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				PayloadSig = data.ReadBytes(BLS_SIGNATURE_SIZE);
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public byte[] IpAddress { get; set; }
			public ushort Port { get; set; }
			public uint ScriptOperatorPayoutSize;
			public Script ScriptOperatorPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateRegistrarTransaction : SpecialTransaction
		{
			public ProviderUpdateRegistrarTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				Mode = data.ReadUInt16();
				PubKeyOperator = data.ReadBytes(BLS_PUBLIC_KEY_SIZE);
				KeyIdVoting = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptPayoutSize);
				ScriptPayout = new Script(data.ReadBytes((int)ScriptPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				if (data.BaseStream.Position < data.BaseStream.Length)
				{
					bs.ReadWriteAsVarInt(ref PayloadSigSize);
					PayloadSig = data.ReadBytes((int)PayloadSigSize);
				}
				else
					PayloadSig = new byte[0];
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public ushort Mode { get; set; }
			public byte[] PubKeyOperator { get; set; }
			public uint160 KeyIdVoting { get; set; }
			public uint ScriptPayoutSize;
			public Script ScriptPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateRevocationTransaction : SpecialTransaction
		{
			public ProviderUpdateRevocationTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				Reason = data.ReadUInt16();
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				PayloadSig = data.ReadBytes(BLS_SIGNATURE_SIZE);
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public ushort Reason { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public abstract class SpecialTransactionWithHeight : SpecialTransaction
		{
			protected SpecialTransactionWithHeight(byte[] extraPayload) : base(extraPayload)
			{
				Height = data.ReadUInt32();
			}

			/// <summary>
			/// Height of the block
			/// </summary>
			public uint Height { get; set; }
		}

		/// <summary>
		/// For ThoughtTransactionType.MasternodeListMerkleProof
		/// https://github.com/thoughtnetwork/dips/blob/master/dip-0004.md
		/// Only needs deserialization here, ExtraPayload can still be serialized
		/// </summary>
		public class CoinbaseSpecialTransaction : SpecialTransactionWithHeight
		{
			public CoinbaseSpecialTransaction(byte[] extraPayload) : base(extraPayload)
			{
				MerkleRootMNList = new uint256(data.ReadBytes(SHA256_HASH_SIZE));
				MakeSureWeAreAtEndOfPayload();
			}

			/// <summary>
			/// Merkle root of the masternode list
			/// </summary>
			public uint256 MerkleRootMNList { get; set; }
		}

		/// <summary>
		/// https://github.com/thoughtevo/thoughtcore-lib/blob/master/lib/transaction/payload/commitmenttxpayload.js
		/// </summary>
		public class QuorumCommitmentTransaction : SpecialTransactionWithHeight
		{
			public QuorumCommitmentTransaction(byte[] extraPayload) : base(extraPayload)
			{
				Commitment = new QuorumCommitment(data);
				MakeSureWeAreAtEndOfPayload();
			}

			public QuorumCommitment Commitment { get; set; }
		}

		public class QuorumCommitment
		{
			public QuorumCommitment(BinaryReader data)
			{
				QfcVersion = data.ReadUInt16();
				LlmqType = data.ReadByte();
				QuorumHash = new uint256(data.ReadBytes(SpecialTransaction.SHA256_HASH_SIZE));
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref SignersSize);
				Signers = data.ReadBytes(((int)SignersSize + 7) / 8);
				bs.ReadWriteAsVarInt(ref ValidMembersSize);
				ValidMembers = data.ReadBytes(((int)ValidMembersSize + 7) / 8);
				QuorumPublicKey = data.ReadBytes(SpecialTransaction.BLS_PUBLIC_KEY_SIZE);
				QuorumVvecHash = new uint256(data.ReadBytes(SpecialTransaction.SHA256_HASH_SIZE));
				QuorumSig = data.ReadBytes(SpecialTransaction.BLS_SIGNATURE_SIZE);
				Sig = data.ReadBytes(SpecialTransaction.BLS_SIGNATURE_SIZE);
			}

			public ushort QfcVersion { get; set; }
			public byte LlmqType { get; set; }
			public uint256 QuorumHash { get; set; }
			public uint SignersSize;
			public byte[] Signers { get; set; }
			public uint ValidMembersSize;
			public byte[] ValidMembers { get; set; }
			public byte[] QuorumPublicKey { get; set; }
			public uint256 QuorumVvecHash { get; set; }
			public byte[] QuorumSig { get; set; }
			public byte[] Sig { get; set; }
		}

		/// <summary>
		/// https://docs.thought.org/en/stable/merchants/technical.html#v0-13-0-integration-notes
		/// </summary>
		public class ThoughtTransaction : Transaction
		{
			public uint ThoughtVersion => Version & 0xffff;
			public ThoughtTransactionType ThoughtType => (ThoughtTransactionType)((Version >> 16) & 0xffff);
			public byte[] ExtraPayload = new byte[0];
			public ProviderRegistrationTransaction ProRegTx =>
				ThoughtType == ThoughtTransactionType.MasternodeRegistration
					? new ProviderRegistrationTransaction(ExtraPayload)
					: null;
			public ProviderUpdateServiceTransaction ProUpServTx =>
				ThoughtType == ThoughtTransactionType.UpdateMasternodeService
					? new ProviderUpdateServiceTransaction(ExtraPayload)
					: null;
			public ProviderUpdateRegistrarTransaction ProUpRegTx =>
				ThoughtType == ThoughtTransactionType.UpdateMasternodeOperator
					? new ProviderUpdateRegistrarTransaction(ExtraPayload)
					: null;
			public ProviderUpdateRevocationTransaction ProUpRevTx =>
				ThoughtType == ThoughtTransactionType.MasternodeRevocation
					? new ProviderUpdateRevocationTransaction(ExtraPayload)
					: null;
			public CoinbaseSpecialTransaction CbTx =>
				ThoughtType == ThoughtTransactionType.MasternodeListMerkleProof
					? new CoinbaseSpecialTransaction(ExtraPayload)
					: null;
			public QuorumCommitmentTransaction QcTx =>
				ThoughtType == ThoughtTransactionType.QuorumCommitment
					? new QuorumCommitmentTransaction(ExtraPayload)
					: null;

			public override void ReadWrite(BitcoinStream stream)
			{
				base.ReadWrite(stream);
				// Support for Thought 0.13 extraPayload for Special Transactions
				// https://github.com/thoughtnetwork/dips/blob/master/dip-0002-special-transactions.md
				if (ThoughtVersion >= 3 && ThoughtType != ThoughtTransactionType.StandardTransaction)
				{
					// Extra payload size is VarInt
					uint extraPayloadSize = (uint)ExtraPayload.Length;
					stream.ReadWriteAsVarInt(ref extraPayloadSize);
					if (ExtraPayload.Length != extraPayloadSize)
						ExtraPayload = new byte[extraPayloadSize];
					stream.ReadWrite(ref ExtraPayload);
				}
			}
		}

		public class ThoughtBlock : Block
		{
#pragma warning disable CS0612 // Type or member is obsolete
			public ThoughtBlock(ThoughtBlockHeader h) : base(h)
#pragma warning restore CS0612 // Type or member is obsolete
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Instance.Mainnet.Consensus.ConsensusFactory;
			}

			public override string ToString()
			{
				return "ThoughtBlock " + Header + ", Height=" + GetCoinbaseHeight() +
					", Version=" + Header.Version + ", Txs=" + Transactions.Count;
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("ThoughtCore");
		}

		static uint256 GetPoWHash(BlockHeader header)
		{
			var headerBytes = header.ToBytes();
			var h = SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
			return new uint256(h);
		}

		protected override NetworkBuilder CreateMainnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 1299382,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000000008adb723e6f7a16be978cac979c2173b67752afc6d2a3f80110fe6c72"),
				PowLimit = new Target(new uint256("0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x0000000000000000000000000000000000000000000000000009f10b61052acc"),
				PowTargetTimespan = TimeSpan.FromSeconds(1.618 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(1.618 * 60),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 100,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = ThoughtConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 7 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 9 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 123 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0xFb, 0xC6, 0xA0, 0x0D })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x5A, 0xEB, 0xD8, 0xC6 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("thought"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("thought"))
			.SetMagic(0x59472ee4)
			.SetPort(10618)
			.SetRPCPort(10617)
			.SetMaxP2PVersion(70018)
			.SetName("thought-main")
			.AddAlias("thought-mainnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("phee.thought.live", "phee.thought.live"),
				new DNSSeedData("phi.thought.live", "phi.thought.live"),
				new DNSSeedData("pho.thought.live", "pho.thought.live"),
				new DNSSeedData("phum.thought.live", "phum.thought.live")
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d6c2031a679c5e9120f735629cc45a8eab5f5879aace2ee519f350a3bf983a48f238a95affff001d5cb1a37b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6404ffff001d01044c5b55534120546f6461792031342f4d61722f32303138204861776b696e6727732064656174682c2045696e737465696e27732062697274682c20616e64205069204461793a207768617420646f657320697420616c6c206d65616e3fffffffff01001208ac25000000434104ed28f11f74795344edfdbc1fccb1e6de37c909ab0c2a535aa6a054fca6fd34b05e3ed9822fa00df98698555d7582777afbc355ece13b7a47004ffe58c0b66c08ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 1299382,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 100,
				BIP34Hash = new uint256("0x000000007459c5f4deaaa14268bb8e6989461227ba743509de6ce194bad621c7"),
				PowLimit = new Target(new uint256("0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x0000000000000000000000000000000000000000000000000000002c03520c2c"),
				PowTargetTimespan = TimeSpan.FromSeconds(1.618 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(1.618 * 60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 100,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = ThoughtConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 109 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 193 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 235 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x5D, 0x40, 0x5F, 0x7A })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0xb6, 0xF1, 0x3F, 0x50 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tthought"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tthought"))
			.SetMagic(0x2b9939bf)
			.SetPort(11618)
			.SetRPCPort(11617)
			.SetMaxP2PVersion(70213)
		   .SetName("thought-test")
		   .AddAlias("thought-testnet")
		   .AddDNSSeeds(new[]
		   {
				new DNSSeedData("testnet.phee.thought.live", "testnet.phee.thought.live")
			 })
		   .AddSeeds(new NetworkAddress[0])
		   .SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d6c2031a679c5e9120f735629cc45a8eab5f5879aace2ee519f350a3bf983a48f238a95affff001d5cb1a37b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6404ffff001d01044c5b55534120546f6461792031342f4d61722f32303138204861776b696e6727732064656174682c2045696e737465696e27732062697274682c20616e64205069204461793a207768617420646f657320697420616c6c206d65616e3fffffffff01001208ac25000000434104ed28f11f74795344edfdbc1fccb1e6de37c909ab0c2a535aa6a054fca6fd34b05e3ed9822fa00df98698555d7582777afbc355ece13b7a47004ffe58c0b66c08ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x000000000000000000000000000000000000000000000000000924e924a21715"),
				PowTargetTimespan = TimeSpan.FromSeconds(1.618 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(1.618 * 60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 100,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 144,
				ConsensusFactory = ThoughtConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 140 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 19 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tthought"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tthought"))
			.SetMagic(0xfcc1b7dc)
			.SetPort(18618)
			.SetRPCPort(18617)
			.SetMaxP2PVersion(70213)
			.SetName("thought-reg")
			.AddAlias("thought-regtest")
			.AddDNSSeeds(new DNSSeedData[0])
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000c762a6567f3cc092f0684bb62b7e00a84890b990f07cc71a6bb58d64b98e02e0b9968054ffff7f20ffba10000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6204ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000"); //need to update this
			return builder;
		}
	}
}
