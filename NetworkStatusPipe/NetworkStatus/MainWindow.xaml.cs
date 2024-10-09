using Microsoft.Win32;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas.Parser;
using System.Net.Http;
using System.Text.Json;
using System.Collections.ObjectModel;
using System.IO.Pipes;

namespace NetworkStatus
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        ObservableCollection<Tips> vulnerabilities = new ObservableCollection<Tips>();
        List<string> responseStrings = new List<string>();

        private void btnUploadFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = "PDF File|*.pdf";
            ofd.ShowDialog();

            PdfReader pdfReader = new PdfReader(ofd.FileName);
            PdfDocument pdfDoc = new PdfDocument(pdfReader);

            StringBuilder text = new StringBuilder();

            for (int i = 1; i <= pdfDoc.GetNumberOfPages(); i++)
            {
                text.Append(PdfTextExtractor.GetTextFromPage(pdfDoc.GetPage(i)));
            }

            pdfDoc.Close();

            string pdfContent = text.ToString();

            string ipPattern = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
            Match ipMatch = Regex.Match(pdfContent, ipPattern);
            string ipAddress = ipMatch.Success ? ipMatch.Value : "N/A";

            string vulnerabilityPattern = @"(\d+) - (.*?)\r?\nSynopsis";
            string synopsisPattern = @"Synopsis\r?\n(.*?)\r?\nDescription";
            string descriptionPattern = @"Description\r?\n(.*?)\r?\nSee Also";
            string seeAlsoPattern = @"See Also\r?\n(.*?)\r?\nSolution";
            string solutionPattern = @"Solution\r?\n(.*?)\r?\nRisk Factor";
            string riskFactorPattern = @"Risk Factor\r?\n(.*?)\r?\nCVSS v3\.0 Base Score";
            string cvssv3BaseScorePattern = @"CVSS v3\.0 Base Score\r?\n(.*?)\r?\n";
            string cvssv3TemporalScorePattern = @"CVSS v3\.0 Temporal Score\r?\n(.*?)\r?\n";
            string cvssBaseScorePattern = @"CVSS Base Score\r?\n(.*?)\r?\n";
            string cvssTemporalScorePattern = @"CVSS Temporal Score\r?\n(.*?)\r?\n";
            string referencesPattern = @"References\r?\n(.*?)\r?\n";
            string pluginInformationPattern = @"Plugin Information\r?\n(.*?)\r?\n";

            MatchCollection vulnerabilitiesMatches = Regex.Matches(pdfContent, vulnerabilityPattern, RegexOptions.Singleline);
            foreach (Match match in vulnerabilitiesMatches)
            {
                Tips tip = new Tips();

                tip.IPAddress = ipAddress;
                tip.VulnerabilityID = int.Parse(match.Groups[1].Value.Trim());
                tip.VulnerabilityName = match.Groups[2].Value.Trim();

                Match synopsisMatch = Regex.Match(pdfContent, synopsisPattern, RegexOptions.Singleline);
                if (synopsisMatch.Success)
                {
                    tip.Synopsis = synopsisMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.Synopsis = "unknown";
                }

                Match descriptionMatch = Regex.Match(pdfContent, descriptionPattern, RegexOptions.Singleline);
                if (descriptionMatch.Success)
                {
                    tip.Description = descriptionMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.Description = "unknown";
                }

                Match seeAlsoMatch = Regex.Match(pdfContent, seeAlsoPattern, RegexOptions.Singleline);
                if (seeAlsoMatch.Success)
                {
                    tip.SeeAlso = new List<string>(seeAlsoMatch.Groups[1].Value.Trim().Split('\n'));
                }
                else
                {
                    tip.SeeAlso = ["unknown"];
                }

                Match solutionMatch = Regex.Match(pdfContent, solutionPattern, RegexOptions.Singleline);
                if (solutionMatch.Success)
                {
                    tip.Solution = solutionMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.Solution = "unknown";
                }

                Match riskFactorMatch = Regex.Match(pdfContent, riskFactorPattern, RegexOptions.Singleline);
                if (riskFactorMatch.Success)
                {
                    tip.RiskFactor = riskFactorMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.RiskFactor = "unknown";
                }

                Match cvssv3BaseScoreMatch = Regex.Match(pdfContent, cvssv3BaseScorePattern, RegexOptions.Singleline);
                if (cvssv3BaseScoreMatch.Success)
                {
                    tip.CVSSv3BaseScore = cvssv3BaseScoreMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.CVSSv3BaseScore = "unknown";
                }

                Match cvssv3TemporalScoreMatch = Regex.Match(pdfContent, cvssv3TemporalScorePattern, RegexOptions.Singleline);
                if (cvssv3TemporalScoreMatch.Success)
                {
                    tip.CVSSv3TemporalScore = cvssv3TemporalScoreMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.CVSSv3TemporalScore = "unknown";
                }

                Match cvssBaseScoreMatch = Regex.Match(pdfContent, cvssBaseScorePattern, RegexOptions.Singleline);
                if (cvssBaseScoreMatch.Success)
                {
                    tip.CVSSBaseScore = cvssBaseScoreMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.CVSSBaseScore = "unknown";
                }

                Match cvssTemporalScoreMatch = Regex.Match(pdfContent, cvssTemporalScorePattern, RegexOptions.Singleline);
                if (cvssTemporalScoreMatch.Success)
                {
                    tip.CVSSTemporalScore = cvssTemporalScoreMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.CVSSTemporalScore = "unknown";
                }

                Match referencesMatch = Regex.Match(pdfContent, referencesPattern, RegexOptions.Singleline);
                if (referencesMatch.Success)
                {
                    tip.References = new List<string>(referencesMatch.Groups[1].Value.Trim().Split('\n'));
                }
                else
                {
                    tip.References = ["unknown"];
                }

                Match pluginInformationMatch = Regex.Match(pdfContent, pluginInformationPattern, RegexOptions.Singleline);
                if (pluginInformationMatch.Success)
                {
                    tip.PluginInformation = pluginInformationMatch.Groups[1].Value.Trim();
                }
                else
                {
                    tip.PluginInformation = "unknown";
                }

                vulnerabilities.Add(tip);

            }

            lblIpCim.Content = ipAddress;
            dgResults.ItemsSource = vulnerabilities;
        }

        private async void btnSendData_Click(object sender, RoutedEventArgs e)
        {
            foreach (Tips tip in vulnerabilities)
            {
                string pipeName = "CsServer";

                try
                {
                    using (NamedPipeClientStream pipeClient = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut))
                    {
                        pipeClient.Connect();

                        byte[] buffer = new byte[1024];
                        int bytesRead = pipeClient.Read(buffer, 0, buffer.Length);
                        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                        MessageBox.Show(response);
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Hiba történt: " + ex.Message);
                }
            }
        }
    }
}