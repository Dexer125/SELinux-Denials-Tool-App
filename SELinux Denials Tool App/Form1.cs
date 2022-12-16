using System.IO;
using System.Linq;
using System.Windows.Forms;

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
                textBox1.Text = ofd.FileName;

                cut = ofd.SafeFileName;
                filename = ofd.FileName;
                indexOfFilename = filename.IndexOf(cut);
                filenamePath = filename.Remove(indexOfFilename);
                richTextBox1.Text = System.IO.File.ReadAllText(filename);                                 
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            ResolveDenials();
        }

        public void ResolveDenials()
        {
            richTextBox1.Text = "Resolving";

            String path = "";
            String outPath;
            String command;
            String scontext;
            String tcontext;
            String tclass;
            String output;
            String answer;
            String allow = "allow ";
            DateTime now = DateTime.Now;
            String formattedTime = now.ToString("yyyy-MM-dd-HH-mm-ss");
            String outputTxt = filenamePath +"resolvedDenials_" + formattedTime + ".txt";
            int fileNameIndex;
            int count = 0;
            textBox2.Text = outputTxt;

            StreamReader reader = new StreamReader(filename);
            string line;

            
                //File.Create(outputTxt);

            /*
             
             Substring arguments in Java are BeginIndex and EndIndex
            Substring argumetns in C# are StartIndex and Length
             
             */
                
  
            TextWriter tw = new StreamWriter(outputTxt);
            while ((line = reader.ReadLine()) != null){

                //lineLength= line.Length;
                

                if (line.Contains("avc: denied") && line.Contains("tcontext=u:object_r:") && !line.Contains(":s0:"))
                {
                    
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied")+7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0 tcontext") - (line.IndexOf("scontext=u:r:")+13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:object_r:") + 20, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:object_r:")+20));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=")+7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";


                    tw.WriteLine(output);
                    tw.Flush();


                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:r:") && !line.Contains(":s0:"))
                {

                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied") + 7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0 tcontext") - (line.IndexOf("scontext=u:r:") + 13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:r:") + 13, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:r:") + 13));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=") + 7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    tw.WriteLine(output);
                    tw.Flush();
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:r:") && line.Contains(":s0:") && line.Contains(":s0 tclass"))
                {

                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied") + 7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - (line.IndexOf("scontext=u:r:") + 13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:r:") + 13, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:r:") + 13));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=") + 7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    tw.WriteLine(output);
                    tw.Flush();
                }

                else if (line.Contains("avc: denied") && line.Contains("tcontext=u:object_r:") && line.Contains(":s0:") && line.Contains(":s0 tclass"))
                {
                    command = line.Substring(line.IndexOf("denied") + 7, line.IndexOf(" for") - (line.IndexOf("denied")+7));
                    scontext = line.Substring(line.IndexOf("scontext=u:r:") + 13, line.IndexOf(":s0:") - (line.IndexOf("scontext=u:r:")+13));
                    tcontext = line.Substring(line.IndexOf("tcontext=u:object_r:") + 20, line.IndexOf(":s0 tclass") - (line.IndexOf("tcontext=u:object_r:")+20));
                    tclass = line.Substring(line.IndexOf("tclass=") + 7, line.IndexOf("permissive") - (line.IndexOf("tclass=")+7));
                    output = allow + scontext + " " + tcontext + ":" + tclass + command + ";";

                    tw.WriteLine(output);
                    tw.Flush();
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
                    tw.WriteLine(output);
                    tw.Flush();
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
                    tw.WriteLine(output);
                    tw.Flush();


                }

            }
            



            }
            

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }
    }
}