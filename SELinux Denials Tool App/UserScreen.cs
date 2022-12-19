using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace SELinux_Denials_Tool_App
{
    public partial class UserScreen : Form
    {
       
        public UserScreen()
        {
            InitializeComponent();
            
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            MainCode.OpenFile(this);
           
        }

        private void button2_Click(object sender, EventArgs e)
        {
            MainCode.ResolveDenials(this);
        }
        
        private void textBox1_TextChanged(object sender, EventArgs e)
        {
           
        }

        private void richTextBox1_TextChanged(object sender, EventArgs e)
        {

        }
    }
}