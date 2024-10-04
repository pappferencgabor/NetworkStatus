using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkStatus
{
    internal class Tips
    {
        public string IPAddress { get; set; }
        public int VulnerabilityID { get; set; }
        public string VulnerabilityName { get; set; }
        public string Synopsis { get; set; }
        public string Description { get; set; }
        public List<string> SeeAlso { get; set; }
        public string Solution { get; set; }
        public string RiskFactor { get; set; }
        public string CVSSv3BaseScore { get; set; }
        public string CVSSv3TemporalScore { get; set; }
        public string CVSSBaseScore { get; set; }
        public string CVSSTemporalScore { get; set; }
        public List<string> References { get; set; }
        public string PluginInformation { get; set; }
    }
}
