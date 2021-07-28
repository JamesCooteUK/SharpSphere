using System;
using System.Security.Principal;

namespace SharpSphere.Security
{
    public enum SspiPackageType
    {
        Kerberos,
        NTLM,
        Negotiate
    }


    internal class SspiHelper
    {
        private const int MAX_TOKEN_SIZE = 12288;


        public const int STANDARD_CONTEXT_ATTRIBUTES =
            NativeContants.ISC_REQ_CONFIDENTIALITY | NativeContants.ISC_REQ_REPLAY_DETECT |
            NativeContants.ISC_REQ_SEQUENCE_DETECT |
            NativeContants.ISC_REQ_CONNECTION;

        public const int TOKEN_QUERY = 0x00008;

        private readonly string _sAccountName;

        private bool _bGotClientCredentials;
        private bool _bGotServerContext;
        private bool _bGotServerCredentials;
        private SECURITY_HANDLE _hClientContext = new SECURITY_HANDLE(0);
        private SECURITY_HANDLE _hInboundCred = new SECURITY_HANDLE(0);
        private SECURITY_HANDLE _hOutboundCred = new SECURITY_HANDLE(0);
        private SECURITY_HANDLE _hServerContext = new SECURITY_HANDLE(0);

        public SspiHelper()
        {
            WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
            if (windowsIdentity != null)
                _sAccountName = windowsIdentity.Name;
        }

        public SspiHelper(string sRemotePrincipal)
        {
            _sAccountName = sRemotePrincipal;
        }


        public void InitializeClient(out byte[] clientToken, byte[] serverToken, out bool bContinueProcessing,
            SspiPackageType sspiPackageType = SspiPackageType.Negotiate)
        {
            clientToken = null;
            bContinueProcessing = true;

            var clientLifeTime = new SECURITY_INTEGER(0);

            if (!_bGotClientCredentials)
            {
                int result = NativeMethods.AcquireCredentialsHandle(
                    _sAccountName, sspiPackageType.ToString(), NativeContants.SECPKG_CRED_OUTBOUND,
                    IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                    ref _hOutboundCred, ref clientLifeTime);

                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("Couldn't acquire client credentials", result);
                }

                _bGotClientCredentials = true;
            }

            int ss;

            var clientTokenSecBufferDesc = new SecBufferDesc(MAX_TOKEN_SIZE);

            try
            {
                uint contextAttributes;

                if (serverToken == null)
                {
                    ss = NativeMethods.InitializeSecurityContext(
                        ref _hOutboundCred,
                        IntPtr.Zero,
                        _sAccountName, // null string pszTargetName,
                        STANDARD_CONTEXT_ATTRIBUTES,
                        0, //int Reserved1,
                        NativeContants.SECURITY_NATIVE_DREP, //int TargetDataRep
                        IntPtr.Zero, //Always zero first time around...
                        0, //int Reserved2,
                        out _hClientContext, //pHandle CtxtHandle = SecHandle
                        out clientTokenSecBufferDesc, //ref SecBufferDesc pOutput, //PSecBufferDesc
                        out contextAttributes, //ref int pfContextAttr,
                        out clientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp
                }
                else
                {
                    var serverTokenSecBufferDesc = new SecBufferDesc(serverToken);

                    try
                    {
                        ss = NativeMethods.InitializeSecurityContext(
                            ref _hOutboundCred,
                            ref _hClientContext,
                            _sAccountName, // null string pszTargetName,
                            STANDARD_CONTEXT_ATTRIBUTES,
                            0, //int Reserved1,
                            NativeContants.SECURITY_NATIVE_DREP, //int TargetDataRep
                            ref serverTokenSecBufferDesc, //Always zero first time around...
                            0, //int Reserved2,
                            out _hClientContext, //pHandle CtxtHandle = SecHandle
                            out clientTokenSecBufferDesc, //ref SecBufferDesc pOutput, //PSecBufferDesc
                            out contextAttributes, //ref int pfContextAttr,
                            out clientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp
                    }
                    finally
                    {
                        serverTokenSecBufferDesc.Dispose();
                    }
                }

                if (ss != NativeContants.SEC_E_OK && ss != NativeContants.SEC_I_CONTINUE_NEEDED)
                {
                    throw new SspiException("InitializeSecurityContext() failed!!!", ss);
                }

                clientToken = clientTokenSecBufferDesc.GetSecBufferByteArray();
            }
            finally
            {
                clientTokenSecBufferDesc.Dispose();
            }

            bContinueProcessing = ss != NativeContants.SEC_E_OK;
        }

        public void InitializeServer(byte[] clientToken, out byte[] serverToken, out bool bContinueProcessing,
            SspiPackageType sspiPackageType = SspiPackageType.Negotiate)
        {
            serverToken = null;
            bContinueProcessing = true;
            var newLifeTime = new SECURITY_INTEGER(0);

            if (!_bGotServerCredentials)
            {
                int result = NativeMethods.AcquireCredentialsHandle(
                    _sAccountName, sspiPackageType.ToString(), NativeContants.SECPKG_CRED_INBOUND,
                    IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                    ref _hInboundCred, ref newLifeTime);

                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("Couldn't acquire server credentials handle!!!", result);
                }

                _bGotServerCredentials = true;
            }

            var serverTokenSecBufferDesc = new SecBufferDesc(MAX_TOKEN_SIZE);
            var clientTokenSecBufferDesc = new SecBufferDesc(clientToken);

            try
            {
                int ss;
                uint uNewContextAttr;

                if (!_bGotServerContext)
                {
                    ss = NativeMethods.AcceptSecurityContext(
                        ref _hInboundCred, // [in] handle to the credentials
                        IntPtr.Zero,
                        // [in/out] handle of partially formed context.  Always NULL the first time through
                        ref clientTokenSecBufferDesc, // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES, // [in] required context attributes
                        NativeContants.SECURITY_NATIVE_DREP, // [in] data representation on the target
                        out _hServerContext, // [in/out] receives the new context handle    
                        out serverTokenSecBufferDesc, // [in/out] pointer to the output buffers
                        out uNewContextAttr, // [out] receives the context attributes        
                        out newLifeTime); // [out] receives the life span of the security context
                }
                else
                {
                    ss = NativeMethods.AcceptSecurityContext(
                        ref _hInboundCred, // [in] handle to the credentials
                        ref _hServerContext,
                        // [in/out] handle of partially formed context.  Always NULL the first time through
                        ref clientTokenSecBufferDesc, // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES, // [in] required context attributes
                        NativeContants.SECURITY_NATIVE_DREP, // [in] data representation on the target
                        out _hServerContext, // [in/out] receives the new context handle    
                        out serverTokenSecBufferDesc, // [in/out] pointer to the output buffers
                        out uNewContextAttr, // [out] receives the context attributes        
                        out newLifeTime); // [out] receives the life span of the security context
                }

                if (ss != NativeContants.SEC_E_OK && ss != NativeContants.SEC_I_CONTINUE_NEEDED)
                {
                    throw new SspiException("AcceptSecurityContext() failed!!!", ss);
                }

                if (!_bGotServerContext)
                {
                    _bGotServerContext = true;
                }

                serverToken = serverTokenSecBufferDesc.GetSecBufferByteArray();

                bContinueProcessing = ss != NativeContants.SEC_E_OK;
            }
            finally
            {
                clientTokenSecBufferDesc.Dispose();
                serverTokenSecBufferDesc.Dispose();
            }
        }

        public void EncryptMessage(
            byte[] message, bool bUseClientContext, out byte[] encryptedBuffer)
        {
            encryptedBuffer = null;

            SECURITY_HANDLE encryptionContext = _hServerContext;

            if (bUseClientContext)
            {
                encryptionContext = _hClientContext;
            }

            SecPkgContext_Sizes contextSizes;

            int result = NativeMethods.QueryContextAttributes(ref encryptionContext, NativeContants.SECPKG_ATTR_SIZES,
                out contextSizes);
            if (result != NativeContants.SEC_E_OK)
            {
                throw new SspiException("QueryContextAttribute() failed!!!", result);
            }

            var thisSecHelper = new MultipleSecBufferHelper[2];
            thisSecHelper[0] = new MultipleSecBufferHelper(message, SecBufferType.SECBUFFER_DATA);
            thisSecHelper[1] = new MultipleSecBufferHelper(new byte[contextSizes.cbSecurityTrailer],
                SecBufferType.SECBUFFER_TOKEN);

            var descBuffer = new SecBufferDesc(thisSecHelper);

            try
            {
                result = NativeMethods.EncryptMessage(ref encryptionContext, 0, ref descBuffer, 0);

                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("EncryptMessage() failed!!!", result);
                }

                encryptedBuffer = descBuffer.GetSecBufferByteArray();
            }
            finally
            {
                descBuffer.Dispose();
            }
        }

        public void DecryptMessage(int messageLength, byte[] encryptedBuffer, bool bUseClientContext,
            out byte[] decryptedBuffer)
        {
            decryptedBuffer = null;

            SECURITY_HANDLE decryptionContext = _hServerContext;

            if (bUseClientContext)
            {
                decryptionContext = _hClientContext;
            }

            var encryptedMessage = new byte[messageLength];
            Array.Copy(encryptedBuffer, 0, encryptedMessage, 0, messageLength);

            int securityTrailerLength = encryptedBuffer.Length - messageLength;

            var securityTrailer = new byte[securityTrailerLength];
            Array.Copy(encryptedBuffer, messageLength, securityTrailer, 0, securityTrailerLength);

            var thisSecHelper = new MultipleSecBufferHelper[2];
            thisSecHelper[0] = new MultipleSecBufferHelper(encryptedMessage, SecBufferType.SECBUFFER_DATA);
            thisSecHelper[1] = new MultipleSecBufferHelper(securityTrailer, SecBufferType.SECBUFFER_TOKEN);
            var descBuffer = new SecBufferDesc(thisSecHelper);
            try
            {
                uint encryptionQuality;
                int result = NativeMethods.DecryptMessage(ref decryptionContext, ref descBuffer, 0,
                    out encryptionQuality);

                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("DecryptMessage() failed!!!", result);
                }

                decryptedBuffer = new byte[messageLength];
                Array.Copy(descBuffer.GetSecBufferByteArray(), 0, decryptedBuffer, 0, messageLength);
            }
            finally
            {
                descBuffer.Dispose();
            }
        }

        public void SignMessage(byte[] message, bool bUseClientContext, out byte[] signedBuffer,
            ref SECURITY_HANDLE hServerContext)
        {
            signedBuffer = null;

            SECURITY_HANDLE encryptionContext = _hServerContext;

            if (bUseClientContext)
            {
                encryptionContext = _hClientContext;
            }

            SecPkgContext_Sizes contextSizes;
            int result = NativeMethods.QueryContextAttributes(ref encryptionContext, NativeContants.SECPKG_ATTR_SIZES,
                out contextSizes);
            if (result != NativeContants.SEC_E_OK)
            {
                throw new SspiException("QueryContextAttribute() failed!!!", result);
            }

            var thisSecHelper = new MultipleSecBufferHelper[2];
            thisSecHelper[0] = new MultipleSecBufferHelper(message, SecBufferType.SECBUFFER_DATA);
            thisSecHelper[1] = new MultipleSecBufferHelper(new byte[contextSizes.cbMaxSignature],
                SecBufferType.SECBUFFER_TOKEN);

            var descBuffer = new SecBufferDesc(thisSecHelper);

            try
            {
                result = NativeMethods.MakeSignature(ref encryptionContext, 0, ref descBuffer, 0);
                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("MakeSignature() failed!!!", result);
                }

                //SSPIHelper.SignAndVerify(ref _hClientContext,ref hServerContext,ref DescBuffer);
                uint encryptionQuality;
                NativeMethods.VerifySignature(ref _hServerContext, ref descBuffer, 0, out encryptionQuality);

                signedBuffer = descBuffer.GetSecBufferByteArray();
            }
            finally
            {
                descBuffer.Dispose();
            }
        }

        public void VerifyMessage(int messageLength, byte[] signedBuffer, bool bUseClientContext,
            out byte[] verifiedBuffer)
        {
            verifiedBuffer = null;

            SECURITY_HANDLE decryptionContext = _hServerContext;

            if (bUseClientContext)
            {
                decryptionContext = _hClientContext;
            }

            var signedMessage = new byte[messageLength];
            Array.Copy(signedBuffer, 0, signedMessage, 0, messageLength);

            int signatureLength = signedBuffer.Length - messageLength;

            var signature = new byte[signatureLength];
            Array.Copy(signedBuffer, messageLength, signature, 0, signatureLength);

            var thisSecHelper = new MultipleSecBufferHelper[2];
            thisSecHelper[0] = new MultipleSecBufferHelper(signedMessage, SecBufferType.SECBUFFER_DATA);
            thisSecHelper[1] = new MultipleSecBufferHelper(signature, SecBufferType.SECBUFFER_TOKEN);
            var descBuffer = new SecBufferDesc(thisSecHelper);
            try
            {
                uint encryptionQuality;

                int result = NativeMethods.VerifySignature(ref decryptionContext, ref descBuffer, 0,
                    out encryptionQuality);

                if (result != NativeContants.SEC_E_OK)
                {
                    throw new SspiException("VerifySignature() failed!!!", result);
                }

                verifiedBuffer = new byte[messageLength];
                Array.Copy(descBuffer.GetSecBufferByteArray(), 0, verifiedBuffer, 0, messageLength);
            }
            finally
            {
                descBuffer.Dispose();
            }
        }
    }
}
