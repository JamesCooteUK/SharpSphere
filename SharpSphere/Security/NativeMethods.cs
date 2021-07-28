using System;
using System.Runtime.InteropServices;

namespace SharpSphere.Security
{
    public static class NativeContants
    {
        public const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        public const int ISC_REQ_CONNECTION = 0x00000800;

        public const int ISC_REQ_REPLAY_DETECT = 0x00000004;
        public const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;

        public const int SEC_E_OK = 0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;

        public const int SECPKG_ATTR_SIZES = 0;
        public const int SECPKG_CRED_INBOUND = 1;
        public const int SECPKG_CRED_OUTBOUND = 2;
        public const int SECURITY_NATIVE_DREP = 0x10;
    }

    internal static class NativeMethods
    {
        [DllImport("secur32", CharSet = CharSet.Unicode)]
        internal static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr pAuthenticationId, //_LUID AuthenticationID,//pvLogonID, //PLUID
            IntPtr pAuthData, //PVOID
            int pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
            ref SECURITY_INTEGER ptsExpiry); //PTimeStamp //TimeStamp ref

        [DllImport("secur32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential, //PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int reserved1,
            int targetDataRep,
            IntPtr pInput, //PSecBufferDesc SecBufferDesc
            int reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        [DllImport("secur32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential, //PCredHandle
            ref SECURITY_HANDLE phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int reserved1,
            int targetDataRep,
            ref SecBufferDesc secBufferDesc, //PSecBufferDesc SecBufferDesc
            int reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint targetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint targetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int ImpersonateSecurityContext(
            ref SECURITY_HANDLE phContext);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int QueryContextAttributes(
            ref SECURITY_HANDLE phContext,
            uint ulAttribute,
            out SecPkgContext_Sizes pContextAttributes);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int EncryptMessage(
            ref SECURITY_HANDLE phContext,
            uint fQop, //managed ulong == 64 bits!!!
            ref SecBufferDesc pMessage,
            uint messageSeqNo); //managed ulong == 64 bits!!!

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int DecryptMessage(
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pMessage,
            uint messageSeqNo,
            out uint pfQop);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int MakeSignature(
            ref SECURITY_HANDLE phContext, // Context to use
            uint fQop, // Quality of Protection
            ref SecBufferDesc pMessage, // Message to sign
            uint messageSeqNo); // Message Sequence Num.

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int VerifySignature(
            ref SECURITY_HANDLE phContext, // Context to use
            ref SecBufferDesc pMessage, // Message to sign
            uint messageSeqNo, // Message Sequence Num.
            out uint pfQop); // Quality of Protection
    }

    #region NetResource Struct

    [StructLayout(LayoutKind.Sequential)]
    public struct NetResource
    {
        public uint Scope;
        public uint Type;
        public uint DisplayType;
        public uint Usage;
        public string LocalName;
        public string RemoteName;
        public string Comment;
        public string Provider;
    }

    #endregion

    #region Enums

    public enum Scope
    {
        RESOURCE_CONNECTED = 1,
        RESOURCE_GLOBALNET,
        RESOURCE_REMEMBERED,
        RESOURCE_RECENT,
        RESOURCE_CONTEXT
    }

    public enum Type : uint
    {
        RESOURCETYPE_ANY,
        RESOURCETYPE_DISK,
        RESOURCETYPE_PRINT,
        RESOURCETYPE_RESERVED = 8,
        RESOURCETYPE_UNKNOWN = 4294967295
    }

    public enum DisplayType
    {
        RESOURCEDISPLAYTYPE_GENERIC,
        RESOURCEDISPLAYTYPE_DOMAIN,
        RESOURCEDISPLAYTYPE_SERVER,
        RESOURCEDISPLAYTYPE_SHARE,
        RESOURCEDISPLAYTYPE_FILE,
        RESOURCEDISPLAYTYPE_GROUP,
        RESOURCEDISPLAYTYPE_NETWORK,
        RESOURCEDISPLAYTYPE_ROOT,
        RESOURCEDISPLAYTYPE_SHAREADMIN,
        RESOURCEDISPLAYTYPE_DIRECTORY,
        RESOURCEDISPLAYTYPE_TREE,
        RESOURCEDISPLAYTYPE_NDSCONTAINER
    }

    public enum Usage : uint
    {
        RESOURCEUSAGE_CONNECTABLE = 1,
        RESOURCEUSAGE_CONTAINER = 2,
        RESOURCEUSAGE_NOLOCALDEVICE = 4,
        RESOURCEUSAGE_SIBLING = 8,
        RESOURCEUSAGE_ATTACHED = 16,
        RESOURCEUSAGE_ALL = 31,
        RESOURCEUSAGE_RESERVED = 2147483648
    }

    public enum ConnectionFlags : uint
    {
        CONNECT_UPDATE_PROFILE = 1,
        CONNECT_UPDATE_RECENT = 2,
        CONNECT_TEMPORARY = 4,
        CONNECT_INTERACTIVE = 8,
        CONNECT_PROMPT = 16,
        CONNECT_NEED_DRIVE = 32,
        CONNECT_REFCOUNT = 64,
        CONNECT_REDIRECT = 128,
        CONNECT_LOCALDRIVE = 256,
        CONNECT_CURRENT_MEDIA = 512,
        CONNECT_DEFERRED = 1024,
        CONNECT_COMMANDLINE = 2048,
        CONNECT_CMD_SAVECRED = 4096,
        CONNECT_CRED_RESET = 8192,
        CONNECT_RESERVED = 4278190080
    }

    #endregion

    #region for sspi helper

    public enum SecBufferType
    {
        SECBUFFER_VERSION = 0,
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle //=PCtxtHandle
    {
        private readonly uint dwLower;
        private readonly uint dwUpper;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        internal IntPtr pvBuffer;

        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    public struct MultipleSecBufferHelper
    {
        public byte[] Buffer;
        public SecBufferType BufferType;

        public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
        {
            if (buffer == null || buffer.Length == 0)
            {
                throw new ArgumentException("buffer cannot be null or 0 length");
            }

            Buffer = buffer;
            BufferType = bufferType;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc : IDisposable
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers; //Point to SecBuffer

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            var thisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(thisSecBuffer));
            Marshal.StructureToPtr(thisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            var thisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(thisSecBuffer));
            Marshal.StructureToPtr(thisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
        {
            if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
            {
                throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
            }

            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = secBufferBytesArray.Length;

            //Allocate memory for SecBuffer Array....
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);

            for (int index = 0; index < secBufferBytesArray.Length; index++)
            {
                //Super hack: Now allocate memory for the individual SecBuffers
                //and just copy the bit values to the SecBuffer array!!!
                var thisSecBuffer = new SecBuffer(secBufferBytesArray[index].Buffer,
                    secBufferBytesArray[index].BufferType);

                //We will write out bits in the following order:
                //int cbBuffer;
                //int BufferType;
                //pvBuffer;
                //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                //are disposed...
                int currentOffset = index * Marshal.SizeOf(typeof(SecBuffer));
                Marshal.WriteInt32(pBuffers, currentOffset, thisSecBuffer.cbBuffer);
                Marshal.WriteInt32(pBuffers, currentOffset + Marshal.SizeOf(thisSecBuffer.cbBuffer),
                    thisSecBuffer.BufferType);
                Marshal.WriteIntPtr(pBuffers,
                    currentOffset + Marshal.SizeOf(thisSecBuffer.cbBuffer) + Marshal.SizeOf(thisSecBuffer.BufferType),
                    thisSecBuffer.pvBuffer);
            }
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    var thisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    thisSecBuffer.Dispose();
                }
                else
                {
                    for (int index = 0; index < cBuffers; index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                        //SecBuffer and release it...
                        int currentOffset = index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr secBufferpvBuffer = Marshal.ReadIntPtr(pBuffers,
                            currentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(secBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                var thisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                if (thisSecBuffer.cbBuffer > 0)
                {
                    buffer = new byte[thisSecBuffer.cbBuffer];
                    Marshal.Copy(thisSecBuffer.pvBuffer, buffer, 0, thisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int bytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //What we need to do here calculate the total number of bytes we need to copy...
                    int currentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    bytesToAllocate += Marshal.ReadInt32(pBuffers, currentOffset);
                }

                buffer = new byte[bytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Now iterate over the individual buffers and put them together into a
                    //byte array...
                    int currentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int bytesToCopy = Marshal.ReadInt32(pBuffers, currentOffset);
                    IntPtr secBufferpvBuffer = Marshal.ReadIntPtr(
                        pBuffers,
                        currentOffset + Marshal.SizeOf(typeof(int)) +
                        Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(secBufferpvBuffer, buffer, BufferIndex, bytesToCopy);
                    BufferIndex += bytesToCopy;
                }
            }

            return (buffer);
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;

        public SECURITY_INTEGER(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public uint LowPart;
        public uint HighPart;

        public SECURITY_HANDLE(int dummy)
        {
            LowPart = HighPart = 0;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public uint cbMaxToken;
        public uint cbMaxSignature;
        public uint cbBlockSize;
        public uint cbSecurityTrailer;
    };

    #endregion
}
