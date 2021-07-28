using System;

namespace SharpSphere.Security
{
    [Serializable]
    public class SspiException : ApplicationException
    {
        private readonly int _errorCode;

        public SspiException(string message, int errorCode)
            : base(string.Format("{0}. Error Code = '{1:X}'.", message, errorCode))
        {
            _errorCode = errorCode;
        }

        public int ErrorCode
        {
            get { return _errorCode; }
        }
    }
}
