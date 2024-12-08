﻿#pragma checksum "..\..\..\..\MainWindow.xaml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "B19818B5CF88E161D0454E22D7BB26CB91FED756"
//------------------------------------------------------------------------------
// <auto-generated>
//     Ten kod został wygenerowany przez narzędzie.
//     Wersja wykonawcza:4.0.30319.42000
//
//     Zmiany w tym pliku mogą spowodować nieprawidłowe zachowanie i zostaną utracone, jeśli
//     kod zostanie ponownie wygenerowany.
// </auto-generated>
//------------------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;


namespace Cypher {
    
    
    /// <summary>
    /// MainWindow
    /// </summary>
    public partial class MainWindow : System.Windows.Window, System.Windows.Markup.IComponentConnector {
        
        
        #line 6 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button browse;
        
        #line default
        #line hidden
        
        
        #line 8 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button encrypt;
        
        #line default
        #line hidden
        
        
        #line 10 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button decrypt;
        
        #line default
        #line hidden
        
        
        #line 12 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button homeButton;
        
        #line default
        #line hidden
        
        
        #line 14 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.StackPanel decryptPanel;
        
        #line default
        #line hidden
        
        
        #line 15 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button selectKeyIvButton;
        
        #line default
        #line hidden
        
        
        #line 16 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button decryptFileButton;
        
        #line default
        #line hidden
        
        
        #line 17 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox keyText;
        
        #line default
        #line hidden
        
        
        #line 18 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox ivText;
        
        #line default
        #line hidden
        
        
        #line 19 "..\..\..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox extensionText;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "8.0.8.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/Cypher;component/mainwindow.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\..\..\MainWindow.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "8.0.8.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            this.browse = ((System.Windows.Controls.Button)(target));
            
            #line 6 "..\..\..\..\MainWindow.xaml"
            this.browse.Click += new System.Windows.RoutedEventHandler(this.OnBrowseButtonClicked);
            
            #line default
            #line hidden
            return;
            case 2:
            this.encrypt = ((System.Windows.Controls.Button)(target));
            
            #line 8 "..\..\..\..\MainWindow.xaml"
            this.encrypt.Click += new System.Windows.RoutedEventHandler(this.OnEncryptButtonClicked);
            
            #line default
            #line hidden
            return;
            case 3:
            this.decrypt = ((System.Windows.Controls.Button)(target));
            
            #line 10 "..\..\..\..\MainWindow.xaml"
            this.decrypt.Click += new System.Windows.RoutedEventHandler(this.OnDecryptButtonClicked);
            
            #line default
            #line hidden
            return;
            case 4:
            this.homeButton = ((System.Windows.Controls.Button)(target));
            
            #line 12 "..\..\..\..\MainWindow.xaml"
            this.homeButton.Click += new System.Windows.RoutedEventHandler(this.OnHomeButtonClicked);
            
            #line default
            #line hidden
            return;
            case 5:
            this.decryptPanel = ((System.Windows.Controls.StackPanel)(target));
            return;
            case 6:
            this.selectKeyIvButton = ((System.Windows.Controls.Button)(target));
            
            #line 15 "..\..\..\..\MainWindow.xaml"
            this.selectKeyIvButton.Click += new System.Windows.RoutedEventHandler(this.OnSelectKeyIvButtonClicked);
            
            #line default
            #line hidden
            return;
            case 7:
            this.decryptFileButton = ((System.Windows.Controls.Button)(target));
            
            #line 16 "..\..\..\..\MainWindow.xaml"
            this.decryptFileButton.Click += new System.Windows.RoutedEventHandler(this.OnDecryptFileButtonClicked);
            
            #line default
            #line hidden
            return;
            case 8:
            this.keyText = ((System.Windows.Controls.TextBox)(target));
            return;
            case 9:
            this.ivText = ((System.Windows.Controls.TextBox)(target));
            return;
            case 10:
            this.extensionText = ((System.Windows.Controls.TextBox)(target));
            return;
            }
            this._contentLoaded = true;
        }
    }
}

