namespace SharpSphere.Security
{
    public class SspiClient
    {
        private readonly SspiHelper _sspiHelper;
        private readonly SspiPackageType _sspiPackageType;

        private byte[] _clientToken;
        private bool _continueProcessing;

        public SspiClient(string principalName, SspiPackageType sspiPackageType)
        {
            _sspiHelper = new SspiHelper(principalName);
            _sspiPackageType = sspiPackageType;

            _sspiHelper.InitializeClient(out _clientToken, null, out _continueProcessing, _sspiPackageType);
        }

        public byte[] Token
        {
            get { return _clientToken; }
        }

        public void Initialize(byte[] serverToken)
        {
            _sspiHelper.InitializeClient(out _clientToken, serverToken, out _continueProcessing, _sspiPackageType);
        }
    }

}
