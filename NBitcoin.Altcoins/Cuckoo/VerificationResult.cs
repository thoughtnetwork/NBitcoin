namespace NBitcoin.Altcoins.Cuckoo
{
    /// <summary>
    /// Result of Cuckoo proof verification.
    /// </summary>
    public enum VerificationResult
    {
        /// <summary>
        /// Valid proof.
        /// </summary>
        Ok,
        /// <summary>
        /// Edge too big.
        /// </summary>
        TooBig,
        /// <summary>
        /// Edges not ascending.
        /// </summary>
        TooSmall,
        /// <summary>
        /// Non-matching endpoints.
        /// </summary>
        NonMatching,
        /// <summary>
        /// Cycle has a branch.
        /// </summary>
        Branch,
        /// <summary>
        /// Cycle dead-ends.
        /// </summary>
        DeadEnd,
        /// <summary>
        /// Cycle is too short.
        /// </summary>
        ShortCycle
    }
}
