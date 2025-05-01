using System.Windows.Forms;

namespace ARH4
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        private ComboBox cmbInterfaces;
        private Button btnStartStop;
        private TreeView tvPackets;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.cmbInterfaces = new System.Windows.Forms.ComboBox();
            this.btnStartStop = new System.Windows.Forms.Button();
            this.tvPackets = new System.Windows.Forms.TreeView();
            this.SuspendLayout();
            // 
            // cmbInterfaces
            // 
            this.cmbInterfaces.Dock = System.Windows.Forms.DockStyle.Top;
            this.cmbInterfaces.FormattingEnabled = true;
            this.cmbInterfaces.Location = new System.Drawing.Point(0, 0);
            this.cmbInterfaces.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.cmbInterfaces.Name = "cmbInterfaces";
            this.cmbInterfaces.Size = new System.Drawing.Size(1067, 24);
            this.cmbInterfaces.TabIndex = 0;
            this.cmbInterfaces.SelectedIndexChanged += new System.EventHandler(this.cmbInterfaces_SelectedIndexChanged);
            // 
            // btnStartStop
            // 
            this.btnStartStop.Dock = System.Windows.Forms.DockStyle.Top;
            this.btnStartStop.Location = new System.Drawing.Point(0, 24);
            this.btnStartStop.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnStartStop.Name = "btnStartStop";
            this.btnStartStop.Size = new System.Drawing.Size(1067, 28);
            this.btnStartStop.TabIndex = 1;
            this.btnStartStop.Text = "Start";
            this.btnStartStop.UseVisualStyleBackColor = true;
            this.btnStartStop.Click += new System.EventHandler(this.btnStartStop_Click);
            // 
            // tvPackets
            // 
            this.tvPackets.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tvPackets.Location = new System.Drawing.Point(0, 52);
            this.tvPackets.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tvPackets.Name = "tvPackets";
            this.tvPackets.Size = new System.Drawing.Size(1067, 502);
            this.tvPackets.TabIndex = 2;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1067, 554);
            this.Controls.Add(this.tvPackets);
            this.Controls.Add(this.btnStartStop);
            this.Controls.Add(this.cmbInterfaces);
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "Form1";
            this.Text = "Network Traffic Analyzer";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainForm_FormClosing);
            this.ResumeLayout(false);

        }
    }
}