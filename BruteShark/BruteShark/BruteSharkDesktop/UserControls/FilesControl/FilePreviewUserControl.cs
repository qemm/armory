﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace BruteSharkDesktop
{
    public partial class FilePreviewUserControl : UserControl
    {
        private readonly List<string> _imagesFilesExtentions = new List<string> {"jpg", "png", "gif"};

        public FilePreviewUserControl()
        {
            InitializeComponent();
        }

        public void PreviewFile(byte[] data, string extention)
        {
            try
            {
                if (_imagesFilesExtentions.Contains(extention))
                {
                    this.filePreviewSplitContainer.Panel2.Controls.Clear();
                    this.filePreviewSplitContainer.Panel2.BackgroundImageLayout = ImageLayout.Center;
                    this.filePreviewSplitContainer.Panel2.BackgroundImage = byteArrayToImage(data);
                }
            }
            catch 
            { 
            
            }
        }


        private static Image GetImage(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                return (Image.FromStream(ms));
            }
        }

        public Image byteArrayToImage(byte[] byteArrayIn)
        {
            System.Drawing.ImageConverter converter = new System.Drawing.ImageConverter();
            Image img = (Image)converter.ConvertFrom(byteArrayIn);

            return img;
        }

    }
}
