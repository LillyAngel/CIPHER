using MahApps.Metro.Controls;
using System.Windows;

namespace Cypher
{
    public partial class CustomMessageBox : MetroWindow
    {
        public CustomMessageBox(string message)
        {
            InitializeComponent();
            MessageTextBlock.Text = message;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
