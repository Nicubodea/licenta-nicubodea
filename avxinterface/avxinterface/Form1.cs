using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Threading;
using System.Net;
using System.Net.Sockets;

namespace avxinterface
{
    public partial class Form1 : Form
    {
        DataTable alerts = new DataTable();

        public Form1()
        {
            Process.Start("py", "-3 C:\\Users\\nbodea\\Documents\\Training\\Git\\avxcnn\\cnn.py");
            Thread t1 = new Thread(new ThreadStart(InterceptAlerts));
            t1.Start(); 
            InitializeComponent();
            InitGridView();
            InitAlerts();
            button2_Click(null, null);


        }

        public void InterceptAlerts()
        {
            string data = null;
            byte[] bytes = new Byte[1024];

            Console.WriteLine("Intercepting alerts");

            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            Console.WriteLine(ipAddress.ToString());
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 50055);
  
            Socket listener = new Socket(ipAddress.AddressFamily,
                SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                Console.WriteLine("Listening");
                Socket handler = listener.Accept();

                Console.WriteLine("Someone connected");
                    while (true)
                    {
                        bytes = new byte[1024];
                        data = null;
                        int bytesRec = handler.Receive(bytes);
                        data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                        if(bytesRec == 0)
                        {
                            Console.WriteLine("received 0...");
                            break;
                        }
                        Int64 pid = Int64.Parse(data);

                        alerts.Rows.Add(pid);

                    alerts.AcceptChanges();
                    }

                   
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        public void InitGridView()
        {
            dataGridView1.DataSource = GetTable();
            DataGridViewButtonColumn btn = new DataGridViewButtonColumn();
            dataGridView1.Columns.Add(btn);
            btn.HeaderText = "Protection";
            btn.Text = "Protect";
            btn.Name = "Protect";
            btn.UseColumnTextForButtonValue = true;

        }
        
        public void InitAlerts()
        {
            
            alerts.Columns.Add("PID of victim");
            dataGridView2.DataSource = alerts;
        }

        public DataTable GetTable()
        {
            DataTable d = new DataTable();

            Process[] p = Process.GetProcesses();

            d.Columns.Add("Name");
            d.Columns.Add("PID");

            int i = 0;
            foreach(Process x in p)
            {
                d.Rows.Add();
                d.Rows[i][0] = x.ProcessName;
                d.Rows[i][1] = x.Id;
                i = i + 1;
            }

            return d;
        }

        public void GeneralClicker(object sender, EventArgs e)
        {
            Console.WriteLine(((Button)sender).Name);
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.ColumnIndex == 2)
            {
                int row = e.RowIndex;
                int column = 1;
                
                string pid = (string)dataGridView1.Rows[row].Cells[column].Value;
                Console.WriteLine(pid);
                Process.Start("C:\\Users\\nbodea\\Documents\\Training\\Git\\axvdll\\x64\\Debug\\avxinj.exe", pid);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            dataGridView1.Columns.Remove("Protect");
            dataGridView1.Columns.Remove("Name");
            dataGridView1.Columns.Remove("PID");
            InitGridView();
        }
    }

    
}
