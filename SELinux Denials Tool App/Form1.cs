using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace SELinux_Denials_Tool_App
{
    public partial class Form1 : Form
    {
        String filename = String.Empty;
        String filenamePath = String.Empty;
        OpenFileDialog ofd;

        public Form1()
        {
            InitializeComponent();
            
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();

            String cut;
            int indexOfFilename;
            ofd.InitialDirectory = "c:\\";
            ofd.Filter = "txt files (*.txt)|*.txt";
            ofd.RestoreDirectory = true;

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = "Source: " + ofd.FileName;

                cut = ofd.SafeFileName;
                filename = ofd.FileName;
                indexOfFilename = filename.IndexOf(cut);
                filenamePath = filename.Remove(indexOfFilename);
                richTextBox1.AppendText("Opening file...");
                richTextBox1.AppendText(Environment.NewLine + File.ReadAllText(filename));
                richTextBox1.AppendText(Environment.NewLine + "_______________________________________________________________________________________________");
                richTextBox1.ScrollToCaret();
                                                
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            ResolveDenials();
        }

        public void ResolveDenials()
        {
            richTextBox1.AppendText(Environment.NewLine + "Resolving file...");
            richTextBox1.ScrollToCaret();


            String command;
            String scontext;
            String tcontext;
            String tclass;
            String output;
            String allow = "allow ";
            DateTime now = DateTime.Now;
            String formattedTime = now.ToString("yyyy-MM-dd-HH-mm-ss");
            String outputTxt = filenamePath +"resolvedDenials_" + formattedTime + ".txt";
            String outputTxtTemp = filenamePath + "outputTemp.txt";
            int count = 0;

            StreamReader reader = new StreamReader(filename);
            TextWriter writer = new StreamWriter(outputTxtTemp);
            String line;

            
                //File.Create(outputTxt);

            /*
             
             Substring arguments in Java are BeginIndex and EndIndex
            Substring argumetns in C# are StartIndex and Length
             
             */
                
  
            
            while ((line = reader.ReadLine()) != null){

                //lineLength= line.Length;
                

                if (line.Contains("avc: denied") && line.Contains("tcontext=u:object_r:") && !line.Contains(":s0:"))
                {
                    
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied")+7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0 tcontext") - (line.IndexOf("scontext=u:r:")+13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:object_r:") + 20, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:object_r:")+20));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=")+7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";


                    writer.WriteLine(output);
                    writer.Flush();
                    count++;


                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:r:") && !line.Contains(":s0:"))
                {

                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied") + 7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0 tcontext") - (line.IndexOf("scontext=u:r:") + 13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:r:") + 13, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:r:") + 13));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=") + 7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    writer.WriteLine(output);
                    writer.Flush();
                    count++;
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:r:") && line.Contains(":s0:") && line.Contains(":s0 tclass"))
                {

                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied") + 7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - (line.IndexOf("scontext=u:r:") + 13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:r:") + 13, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:r:") + 13));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=") + 7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    writer.WriteLine(output);
                    writer.Flush();
                    count++;
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:object_r:") && line.Contains(":s0:") && line.Contains(":s0 tclass"))
                {
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied")+7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - (line.IndexOf("scontext=u:r:")+13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:object_r:") + 20, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:object_r:")+20));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=")+7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    writer.WriteLine(output);
                    writer.Flush();
                    count++;
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:r:") && line.Contains(":s0:") && !line.Contains(":s0 tclass"))
                {
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - line.IndexOf("denied"));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - line.IndexOf("scontext=u:r:"));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:r:") + 13, line.IndexOf(" tclass") - line.IndexOf("tcontext=u:r:"));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - line.IndexOf("tclass="));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    // Delete unwanted characters in output
                    if (output.Contains(":s0:"))
                    {
                        output = output.Replace(output.Substring(output.IndexOf(":s0:"), (output.IndexOf(";") + 1) - output.IndexOf(":s0:")), "");
                        output = output + ":" + tclass + command + ";";
                    }
                    writer.WriteLine(output);
                    writer.Flush();
                    count++;
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:object_r:") && line.Contains(":s0:") && !line.Contains(":s0 tclass"))
                {
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied")+7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - (line.IndexOf("scontext=u:r:")+13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:object_r:") + 20, line.IndexOf(" tclass") - (line.IndexOf("tcontext=u:object_r:")+20));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=")+7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    if (output.Contains(":s0:"))
                    {
                        output = output.Replace(output.Substring(output.IndexOf(":s0:"), (output.IndexOf(";") + 1) - output.IndexOf(":s0:")), "");
                        output = output + ":" + tclass + command + ";";
                    }
                    writer.WriteLine(output);
                    writer.Flush();
                    count++;


                }

            }
            reader.Close(); 
            writer.Close();
            textBox2.Text = "Destination: " + outputTxt;

            if (count != 0)
            {
                RemoveDuplicates(outputTxt, outputTxtTemp);
            }
            else{

                richTextBox1.AppendText("No logs in file, check if your kernel supports Audit logging or open another file...");
                richTextBox1.ScrollToCaret();
                return;
            }
            
        }

        public void RemoveDuplicates(String outpuTxt, String outputTxtTemp)
        {
            StreamReader reader = new StreamReader(outputTxtTemp);
            TextWriter writer = new StreamWriter(outpuTxt);
            HashSet<String> hashSet = new HashSet<String>();
            String line;
            while ((line = reader.ReadLine()) != null)
            {

                // Write only if not present in hashset
                if (hashSet.Add(line))
                {
                   writer.WriteLine(line);
                }
                else
                {
                    reader.ReadLine();
                }
              
            }

            writer.Flush();
            reader.Close();
            writer.Close();
            File.Delete(outputTxtTemp);
            richTextBox1.AppendText(Environment.NewLine + "Resolved, check destination folder...");
            richTextBox1.ScrollToCaret();

        }
        



        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }
    }
}