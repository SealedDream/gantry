using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// WIN-COLD-LIGHT: the first frame builds only what it paints. Cold start after a reboot stayed over its 1.0 s budget
// (median 1290 ms, q-cold-reboot5) after the prefetch and image-scan work, so the window itself got lighter:
// - the title bar (library switcher, tab strip, New menu, Bastion menu: 98 of the window's 235 XAML elements) is collapsed
//   until the content moves into the title bar after the first frame; it is now TitleBarView.xaml, built then;
// - the details pane is hidden until something is selected; it is now InspectorView.xaml, built when first shown (the
//   "null until first shown" contract of #656 is back);
// - the Credentials section (a TreeView) and Recent sessions (a ListView) were laid out in the first frame although nobody
//   can use them before it; they are built right after it;
// - the sidebar's "Search or connect" TextBox loads WinUIEdit.dll and its text services (86 ms of page-ins and 33 ms of
//   set-up in the XAML load of a slow boot, q-cold-trace6); the first frame paints a look-alike made of the TextBox's own
//   theme resources (MainWindow.xaml, SearchPlaceholder) and the TextBox takes its place right after it.
// The named controls keep their names as properties below, so the rest of MainWindow reads them as before. Reading a
// title-bar control builds the title bar if it is not built yet: always correct, only slower. The start-up steps that run
// before the first frame skip their title-bar part until it exists (TitleBarBuilt applies it). Start-up marks
// titlebar-built, inspector-built and credentials-built show when each was built. Test builds: BASTION_COLD_EAGER=1 builds
// all of it before the first frame again, for an A/B in one build.
public sealed partial class MainWindow
{
    private TitleBarView? _titleBar;
    private InspectorView? _inspectorView;
    private CredentialsPane? _credentialsPane;

    /// <summary>Set when the work kept back until after the first frames starts (StartDeferredServices).</summary>
    private bool _firstFramesDone;

    // Title-bar state set before the title bar exists; TitleBarBuilt applies it.
    private string? _compactLibraryName;
    private bool _verticalTabsWanted;
    private bool _moreDeleteEnabled = true;

    /// <summary>The title bar (TitleBarView), built on first use.</summary>
    private TitleBarView Chrome => _titleBar ?? BuildTitleBar();

    /// <summary>The title bar's root grid (named Toolbar in the XAML before WIN-COLD-LIGHT).</summary>
    private TitleBarView Toolbar => Chrome;
    private Button ShowSidebarButton => Chrome.ShowSidebarButton;
    private Grid CompactLibraryHost => Chrome.CompactLibraryHost;
    private DropDownButton CompactLibraryButton => Chrome.CompactLibraryButton;
    private TextBlock CompactLibraryText => Chrome.CompactLibraryText;
    private MenuFlyout CompactLibraryFlyout => Chrome.CompactLibraryFlyout;
    private Grid TabBar => Chrome.TabBar;
    private Button TabOverviewButton => Chrome.TabOverviewButton;
    private TextBlock TabCountText => Chrome.TabCountText;
    private Flyout AllTabsFlyout => Chrome.AllTabsFlyout;
    private Button TabScrollLeftButton => Chrome.TabScrollLeftButton;
    private Grid TabArea => Chrome.TabArea;
    private ScrollViewer TabScroller => Chrome.TabScroller;
    private StackPanel TabStrip => Chrome.TabStrip;
    private Button TabScrollRightButton => Chrome.TabScrollRightButton;
    private Button NewTerminalButton => Chrome.NewTerminalButton;
    private Button TerminalProfilesButton => Chrome.TerminalProfilesButton;
    private MenuFlyoutItem CompactNewConnectionItem => Chrome.CompactNewConnectionItem;
    private MenuFlyoutSeparator WslSeparator => Chrome.WslSeparator;
    private MenuFlyoutItem WslPlaceholder => Chrome.WslPlaceholder;
    private MenuFlyout MoreMenu => Chrome.MoreMenu;
    private MenuFlyoutSubItem TerminalColorsMenu => Chrome.TerminalColorsMenu;
    private MenuFlyoutSubItem TypeDefaultsMenu => Chrome.TypeDefaultsMenu;
    private MenuFlyoutItem MoreQuickConnect => Chrome.MoreQuickConnect;
    private MenuFlyoutItem MorePalette => Chrome.MorePalette;
    private MenuFlyoutItem MoreDelete => Chrome.MoreDelete;
    private MenuFlyoutSubItem DocumentsMenu => Chrome.DocumentsMenu;
    private MenuFlyoutItem MoreSendVariables => Chrome.MoreSendVariables;
    private MenuFlyoutItem MoreFiles => Chrome.MoreFiles;
    private MenuFlyoutItem MoreSplitRight => Chrome.MoreSplitRight;
    private MenuFlyoutItem MoreSplitDown => Chrome.MoreSplitDown;
    private ToggleMenuFlyoutItem NavToggle => Chrome.NavToggle;
    private ToggleMenuFlyoutItem NavAutoHideToggle => Chrome.NavAutoHideToggle;
    private ToggleMenuFlyoutItem InspectorToggle => Chrome.InspectorToggle;

    private TextBox? _searchBox;
    private string? _searchHint;
    private const string SearchTip = "Search or connect: filter the library; Enter connects to the top match or to a typed address (Ctrl+F, Ctrl+L)";

    /// <summary>The sidebar's "Search or connect" box, built right after the first frame or on first use.</summary>
    private TextBox SearchBox => _searchBox ?? BuildSearchBox();

    /// <summary>Put the real search box where the first frame's look-alike is (same name, automation id and events as the
    /// TextBox the XAML had before WIN-COLD-LIGHT).</summary>
    private TextBox BuildSearchBox()
    {
        if (_searchBox is { } built) return built;
        var box = new TextBox
        {
            Name = "SearchBox",
            PlaceholderText = "Search or connect",
            Padding = Ui.Thickness("SearchBoxPadding"),
            IsSpellCheckEnabled = false,
        };
        AutomationProperties.SetAutomationId(box, "SearchConnectBox");
        AutomationProperties.SetName(box, "Search connections");
        AutomationProperties.SetLandmarkType(box, AutomationLandmarkType.Search);
        ToolTipService.SetToolTip(box, _searchHint ?? SearchTip);
        box.TextChanged += SearchBox_TextChanged;
        box.KeyDown += SearchBox_KeyDown;
        _searchBox = box;
        var at = SearchHost.Children.IndexOf(SearchPlaceholder);
        if (at >= 0) SearchHost.Children.RemoveAt(at);
        else at = 0;
        SearchHost.Children.Insert(at, box); // under the search glyph, as in the XAML
        StartupProbe.Mark("searchbox-built");
        return box;
    }

    /// <summary>The search box's tip counts connections and sessions; kept until the box exists.</summary>
    private void SetSearchHint(string hint)
    {
        _searchHint = hint;
        if (_searchBox is not null) ToolTipService.SetToolTip(_searchBox, hint);
    }

    /// <summary>The details pane: null until it is first shown (EnsureInspector builds it).</summary>
    private InspectorView? Inspector => _inspectorView;

    /// <summary>The details pane, built (hidden) if it is not built yet.</summary>
    private InspectorView BuiltInspector
    {
        get
        {
            EnsureInspector();
            return _inspectorView!;
        }
    }
    private TextBlock InspectorTitle => BuiltInspector.InspectorTitle;
    private TextBlock InspectorKind => BuiltInspector.InspectorKind;
    private StackPanel InspectorActions => BuiltInspector.InspectorActions;
    private Button InspectorPrimaryButton => BuiltInspector.InspectorPrimaryButton;
    private Button CopyHostButton => BuiltInspector.CopyHostButton;
    private TextBlock CopyHostLabel => BuiltInspector.CopyHostLabel;
    private Button InspectorPropertiesButton => BuiltInspector.InspectorPropertiesButton;
    private Button InspectorMoreButton => BuiltInspector.InspectorMoreButton;
    private MenuFlyout InspectorMoreMenu => BuiltInspector.InspectorMoreMenu;
    private Button HideInspectorButton => BuiltInspector.HideInspectorButton;
    private StackPanel InspectorBody => BuiltInspector.InspectorBody;
    private StackPanel InspectorFooter => BuiltInspector.InspectorFooter;
    private TextBlock LastConnectedText => BuiltInspector.LastConnectedText;
    private TextBlock LastResultText => BuiltInspector.LastResultText;

    /// <summary>Build the title bar now (idempotent). Until the content moves into the title bar after the first frame it
    /// stays collapsed, as the toolbar always was ("FLASH OK", #145); StartDeferredServices shows it.</summary>
    private TitleBarView BuildTitleBar()
    {
        if (_titleBar is { } built) return built;
        var bar = new TitleBarView();
        _titleBar = bar; // first: the wiring and TitleBarBuilt read the controls through the properties above
        if (!_firstFramesDone && !_demo) bar.Visibility = Visibility.Collapsed;
        WireTitleBar(bar);
        RootGrid.Children.Insert(0, bar); // row 0, first child: where the toolbar was in the XAML
        StartupProbe.Mark("titlebar-built");
        TitleBarBuilt();
        return bar;
    }

    /// <summary>The title-bar part of the start-up steps that ran before the title bar existed.</summary>
    private void TitleBarBuilt()
    {
        UpdateAllTabsButton();
        if (_compactLibraryName is { } name) UpdateCompactLibrary(name);
        UpdateCompactLibraryWidth();
        ApplyTabOrientation(_verticalTabsWanted);
        MoreDelete.IsEnabled = _moreDeleteEnabled;
        _passthrough = null; // the caption's clickable regions change with the controls
        UpdateToolbarLabels();
    }

    /// <summary>More › Delete follows the selection; kept until the title bar exists.</summary>
    private void SetMoreDeleteEnabled(bool enabled)
    {
        _moreDeleteEnabled = enabled;
        if (_titleBar is not null) MoreDelete.IsEnabled = enabled;
    }

    /// <summary>The events the XAML wired before WIN-COLD-LIGHT, to the same handlers.</summary>
    private void WireTitleBar(TitleBarView v)
    {
        v.ShowSidebarButton.Click += ShowSidebar_Click;
        v.TabBar.SizeChanged += TabScroller_SizeChanged;
        v.AllTabsFlyout.Opening += AllTabsFlyout_Opening;
        v.AllTabsFlyout.Opened += AllTabsFlyout_Opened;
        v.TabScrollLeftButton.Click += TabScrollLeft_Click;
        v.TabArea.SizeChanged += TabScroller_SizeChanged;
        v.TabScroller.ViewChanged += TabScroller_ViewChanged;
        v.TabScrollRightButton.Click += TabScrollRight_Click;
        v.NewTerminalButton.Click += NewLocalShell_Click;
        v.HomeButton.Click += Home_Click;
        v.InspectorToggleButton.Click += InspectorButton_Click;
        v.ProfilesMenu.Opening += TerminalProfiles_Opening;
        v.CompactNewConnectionItem.Click += NewConnection_Click;
        v.CompactNewFromTemplateItem.Click += NewFromTemplate_Click;
        v.CompactNewFolderItem.Click += NewFolder_Click;
        v.ProfilesLocalShellItem.Click += NewLocalShell_Click;
        v.ProfilesPowerShellItem.Click += NewPowerShell_Click;
        v.WslPlaceholder.Click += NewWsl_Click;
        v.ProfilesAddAllWslItem.Click += AddAllWsl_Click;
        v.MoreMenu.Opening += MoreMenu_Opening;
        v.MoreSettings.Click += Settings_Click;
        v.MoreCheckUpdates.Click += CheckForUpdates_Click;
        v.MoreDiagnostics.Click += ExportDiagnostics_Click;
        v.ZoomInItem.Click += ZoomIn_Click;
        v.ZoomOutItem.Click += ZoomOut_Click;
        v.ZoomResetItem.Click += ZoomReset_Click;
        v.MoreQuickConnect.Click += QuickConnect_Click;
        v.MorePalette.Click += Palette_Click;
        v.MoreDelete.Click += Delete_Click;
        v.MoreCredentials.Click += CredentialManager_Click;
        v.MoreAgent.Click += SshAgent_Click;
        v.MoreGateways.Click += GatewayManager_Click;
        v.MoreTunnels.Click += TunnelManager_Click;
        v.MoreActivity.Click += (_, _) => OpenActivity();
        v.MoreAuditLog.Click += (_, _) => OpenAuditLog();
        v.MorePlugins.Click += (_, _) => OpenPlugins();
        v.MoreWorkspaces.Click += (_, _) => OpenWorkspaceManager();
        v.MoreDeleted.Click += RecentlyDeleted_Click;
        v.MoreHostStatus.Click += HostStatus_Click;
        v.MoreTriggers.Click += Triggers_Click;
        v.MoreMultiExec.Click += MultiExec_Click;
        v.MoreProviders.Click += CredentialProviders_Click;
        v.MoreVaultwarden.Click += Vaultwarden_Click;
        v.MorePasswordGenerator.Click += PasswordGenerator_Click;
        v.MoreImportFile.Click += ImportFile_Click;
        v.MoreImportKeePass.Click += ImportKeePass_Click;
        v.MoreImportSsh.Click += ImportSsh_Click;
        v.MoreExportSsh.Click += ExportSsh_Click;
        v.MoreExportAnsible.Click += ExportAnsible_Click;
        v.MoreAnsibleRun.Click += AnsibleRun_Click;
        v.MoreExportLibrary.Click += ExportLibrary_Click;
        v.MoreSendVariables.Click += SendWithVariables_Click;
        v.MoreFiles.Click += Files_Click;
        v.MoreSplitRight.Click += SplitRight_Click;
        v.MoreSplitDown.Click += SplitDown_Click;
        v.NavToggle.Click += NavToggle_Click;
        v.NavAutoHideToggle.Click += NavAutoHideToggle_Click;
        v.InspectorToggle.Click += InspectorToggle_Click;
    }

    /// <summary>Build the details pane, hidden, in the layer's third column (where it was in the XAML).</summary>
    private InspectorView BuildInspectorView()
    {
        var view = new InspectorView();
        view.InspectorPrimaryButton.Click += InspectorPrimary_Click;
        view.CopyHostButton.Click += CopyHost_Click;
        view.InspectorPropertiesButton.Click += Properties_Click;
        view.InspectorMoreMenu.Opening += InspectorMoreMenu_Opening;
        view.HideInspectorButton.Click += HideInspector_Click;
        Grid.SetColumn(view, 2);
        view.Visibility = Visibility.Collapsed; // ApplyInspectorLayout shows it
        _inspectorView = view;
        LayerGrid.Children.Add(view);
        StartupProbe.Mark("inspector-built");
        return view;
    }

    /// <summary>The Credentials section under the tree (CredentialsPane.xaml), in the navigation pane's row 3. Drawn at
    /// once unless the first tree load (Reload, which draws it) is still to come.</summary>
    private void BuildCredentialsPane(bool draw = true)
    {
        if (_credentialsPane is not null || _windowClosed) return;
        var pane = new CredentialsPane();
        Grid.SetRow(pane, 3);
        _credentialsPane = pane;
        // Before the bottom bar, where it was in the XAML: Tab order and the UIA tree follow the children's order.
        NavPane.Children.Insert(NavPane.Children.IndexOf(NavBottomBar), pane);
        StartupProbe.Mark("credentials-built");
        if (draw) RefreshCredentialsPane();
    }

    /// <summary>Snapshot runs (demo data, driven from the first frame) and test builds with BASTION_COLD_EAGER=1 build
    /// everything before the first frame, as before WIN-COLD-LIGHT.</summary>
    private bool BuildsEverythingFirst => _demo || TestHooks.ColdEager;

    /// <summary>For <see cref="BuildsEverythingFirst"/>: build it all in the constructor, before the first tree load. In the
    /// BASTION_COLD_EAGER A/B the marks (eager-start, titlebar-built, inspector-built, credentials-built) show each part's cost.</summary>
    private void BuildBeforeFirstFrame()
    {
        if (!BuildsEverythingFirst) return;
        StartupProbe.Mark("eager-start");
        BuildSearchBox();
        BuildTitleBar();
        EnsureInspector();
        BuildCredentialsPane(draw: false);
    }

    /// <summary>After the first frames: the Credentials section and Recent sessions (StartDeferredServices).</summary>
    private void BuildAfterFirstFrame()
    {
        if (_closed) return;
        BuildCredentialsPane();
        if (!_tabs.Any(IsDocked)) RefreshRecents();
    }
}
