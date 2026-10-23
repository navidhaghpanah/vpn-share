using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace VpnShare;

internal static class Glass
{
    public static readonly Color Ink=Color.FromArgb(241,247,255), Muted=Color.FromArgb(151,173,197), Cyan=Color.FromArgb(103,233,218);
    public static GraphicsPath Round(RectangleF r,float radius)
    {
        float d=Math.Min(radius*2,Math.Min(r.Width,r.Height));var path=new GraphicsPath();
        if(d<=0){path.AddRectangle(r);return path;}
        path.AddArc(r.X,r.Y,d,d,180,90);path.AddArc(r.Right-d,r.Y,d,d,270,90);
        path.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);path.AddArc(r.X,r.Bottom-d,d,d,90,90);path.CloseFigure();return path;
    }
    public static void Text(Graphics g,string text,Font font,Color color,Rectangle area,TextFormatFlags alignment=TextFormatFlags.Left|TextFormatFlags.VerticalCenter)
        =>TextRenderer.DrawText(g,text,font,area,color,alignment|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix|TextFormatFlags.PreserveGraphicsClipping|TextFormatFlags.PreserveGraphicsTranslateTransform);
    public static void NativeBackdrop(Form form)
    {
        if(!OperatingSystem.IsWindowsVersionAtLeast(10,0,22000))return;
        // The custom window region owns the outline. A second DWM radius and
        // acrylic backdrop can expose a mismatched grey rim outside that outline.
        int rounded=1,dark=1;DwmSetWindowAttribute(form.Handle,33,ref rounded,4);DwmSetWindowAttribute(form.Handle,20,ref dark,4);
        if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22621)){int backdrop=1;DwmSetWindowAttribute(form.Handle,38,ref backdrop,4);}
    }
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd,int attr,ref int value,int size);
}

internal class GlassCard : Panel
{
    public int Radius{get;set;}=24;
    public GlassCard(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.SupportsTransparentBackColor,true);BackColor=Color.Transparent;}
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
        var bounds=new RectangleF(1,1,Width-3,Height-3);using var path=Glass.Round(bounds,Radius);
        using var fill=new LinearGradientBrush(bounds,Color.FromArgb(27,255,255,255),Color.FromArgb(8,170,209,244),108);
        g.FillPath(fill,path);using var edge=new LinearGradientBrush(bounds,Color.FromArgb(87,233,248,255),Color.FromArgb(18,210,230,255),115);
        using var pen=new Pen(edge,1);g.DrawPath(pen,path);
        using var inner=Glass.Round(new RectangleF(3,3,Width-7,Height-7),Radius-2);using var line=new Pen(Color.FromArgb(8,255,255,255));g.DrawPath(line,inner);
    }
}

internal sealed class GlassButton : Control
{
    public bool Primary{get;set;}
    public bool Selected{get;set;}
    bool hover;
    public GlassButton()
    {
        SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.SupportsTransparentBackColor,true);
        SetStyle(ControlStyles.Selectable|ControlStyles.StandardClick,true);
        BackColor=Color.Transparent;ForeColor=Glass.Ink;AccessibleRole=AccessibleRole.PushButton;
        Cursor=Cursors.Hand;Font=new Font("Segoe UI",10,FontStyle.Bold);Height=40;TabStop=true;
    }
    protected override void OnResize(EventArgs e){base.OnResize(e);if(Width<2||Height<2)return;using var path=Glass.Round(new RectangleF(0,0,Width,Height),Math.Min(22,Height/2));var old=Region;Region=new Region(path);old?.Dispose();}
    protected override void OnMouseDown(MouseEventArgs e){if(Enabled)Focus();base.OnMouseDown(e);}
    protected override void OnKeyDown(KeyEventArgs e){base.OnKeyDown(e);if(e.KeyCode is Keys.Enter or Keys.Space){e.Handled=true;e.SuppressKeyPress=true;if(Enabled)OnClick(EventArgs.Empty);}}
    protected override void OnGotFocus(EventArgs e){base.OnGotFocus(e);Invalidate();}
    protected override void OnLostFocus(EventArgs e){base.OnLostFocus(e);Invalidate();}
    protected override void OnMouseEnter(EventArgs e){hover=true;Invalidate();base.OnMouseEnter(e);}
    protected override void OnMouseLeave(EventArgs e){hover=false;Invalidate();base.OnMouseLeave(e);}
    protected override void OnPaint(PaintEventArgs e)
    {
        var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
        var bounds=new RectangleF(1,1,Width-3,Height-3);using var path=Glass.Round(bounds,Math.Min(22,Height/2));
        Color top,bottom,ink;
        if(Primary){top=Color.FromArgb(226,255,251);bottom=Color.FromArgb(127,231,224);ink=Color.FromArgb(13,48,62);}
        else if(Selected){top=Color.FromArgb(56,115,139);bottom=Color.FromArgb(37,82,106);ink=Glass.Ink;}
        else{top=hover?Color.FromArgb(53,81,103):Color.FromArgb(38,62,83);bottom=hover?Color.FromArgb(38,66,89):Color.FromArgb(27,46,67);ink=Glass.Ink;}
        if(!Enabled){top=Color.FromArgb(35,52,69);bottom=Color.FromArgb(27,42,58);ink=Glass.Muted;}
        using var brush=new LinearGradientBrush(bounds,top,bottom,90);g.FillPath(brush,path);
        using var border=new Pen(Color.FromArgb(Primary?150:hover?95:40,220,244,255));g.DrawPath(border,path);
        if(Focused){using var ring=Glass.Round(new RectangleF(4,4,Width-9,Height-9),18);using var p=new Pen(Glass.Cyan);g.DrawPath(p,ring);}
        Glass.Text(g,Text,Font,ink,ClientRectangle,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
    }
}

internal sealed class GlassCombo : Control
{
    public List<object> Items{get;}=new();
    int selected=-1;
    public int SelectedIndex{get=>selected;set{selected=value>=0&&value<Items.Count?value:-1;Invalidate();SelectedIndexChanged?.Invoke(this,EventArgs.Empty);}}
    public object? SelectedItem=>selected>=0&&selected<Items.Count?Items[selected]:null;
    public event EventHandler? SelectedIndexChanged;
    ToolStripDropDown? popup;
    public GlassCombo()
    {
        SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.SupportsTransparentBackColor|ControlStyles.Selectable,true);
        BackColor=Color.Transparent;ForeColor=Glass.Ink;Font=new Font("Segoe UI",11);Height=38;Cursor=Cursors.Hand;TabStop=true;AccessibleRole=AccessibleRole.ComboBox;
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;var r=new RectangleF(1,1,Width-3,Height-3);using var path=Glass.Round(r,12);
        using var fill=new SolidBrush(Color.FromArgb(30,255,255,255));g.FillPath(fill,path);using var line=new Pen(Color.FromArgb(Focused?150:48,210,241,255));g.DrawPath(line,path);
        Glass.Text(g,SelectedItem?.ToString()??"Choose a connection",Font,Enabled?ForeColor:Glass.Muted,new Rectangle(12,0,Width-42,Height));
        using var arrow=new Pen(Glass.Muted,1.7f){StartCap=LineCap.Round,EndCap=LineCap.Round};g.DrawLines(arrow,new[]{new Point(Width-26,Height/2-2),new Point(Width-21,Height/2+3),new Point(Width-16,Height/2-2)});
    }
    protected override void OnClick(EventArgs e){base.OnClick(e);Focus();Open();}
    protected override void OnKeyDown(KeyEventArgs e){base.OnKeyDown(e);if(e.KeyCode==Keys.Down){SelectedIndex=Math.Min(Items.Count-1,selected+1);e.Handled=true;}else if(e.KeyCode==Keys.Up){SelectedIndex=Math.Max(0,selected-1);e.Handled=true;}else if(e.KeyCode is Keys.Enter or Keys.Space){Open();e.Handled=true;}}
    void Open()
    {
        if(Items.Count==0||!Enabled)return;popup?.Dispose();
        var list=new ListBox{BorderStyle=BorderStyle.None,DrawMode=DrawMode.OwnerDrawFixed,ItemHeight=38,BackColor=Color.FromArgb(29,47,68),ForeColor=Glass.Ink,Font=Font,Size=new Size(Width-8,Math.Min(230,Items.Count*38))};
        foreach(var item in Items)list.Items.Add(item);if(selected<list.Items.Count)list.SelectedIndex=selected;
        list.DrawItem+=(_,e)=>{using var b=new SolidBrush((e.State&DrawItemState.Selected)!=0?Color.FromArgb(52,87,109):list.BackColor);e.Graphics.FillRectangle(b,e.Bounds);if(e.Index>=0)Glass.Text(e.Graphics,list.Items[e.Index]?.ToString()??"",Font,Glass.Ink,new Rectangle(10,e.Bounds.Y,list.Width-18,e.Bounds.Height));};
        var host=new ToolStripControlHost(list){Padding=Padding.Empty,Margin=Padding.Empty,AutoSize=false,Size=list.Size};popup=new ToolStripDropDown{Padding=new Padding(4),BackColor=list.BackColor};popup.Items.Add(host);
        void Choose(){SelectedIndex=list.SelectedIndex;popup?.Close();}
        list.MouseClick+=(_,_)=>Choose();list.KeyDown+=(_,e)=>{if(e.KeyCode==Keys.Enter)Choose();};popup.Show(this,new Point(0,Height+4));list.Focus();
    }
    protected override void Dispose(bool disposing){if(disposing)popup?.Dispose();base.Dispose(disposing);}
}

internal sealed class GlassField : GlassCard
{
    public TextBox Input{get;}=new(){BorderStyle=BorderStyle.None,BackColor=Color.FromArgb(45,68,88),ForeColor=Glass.Ink,Font=new Font("Segoe UI",11)};
    public GlassField()
    {
        Radius=14;Height=45;Controls.Add(Input);Input.Location=new Point(14,12);Input.Anchor=AnchorStyles.Left|AnchorStyles.Top|AnchorStyles.Right;
        Resize+=(_,_)=>Input.Width=Math.Max(20,Width-28);
    }
}

public class GlassForm : Form
{
    Bitmap? backdrop;
    public GlassForm()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint|ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer,true);
        FormBorderStyle=FormBorderStyle.None;BackColor=Color.FromArgb(13,24,43);ForeColor=Glass.Ink;
        Font=new Font("Segoe UI",10);StartPosition=FormStartPosition.CenterScreen;AutoScaleMode=AutoScaleMode.Dpi;
    }
    protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Glass.NativeBackdrop(this);}
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);if(Width<20||Height<20)return;
        using var outline=Glass.Round(new RectangleF(0,0,Width,Height),32);
        var previous=Region;Region=new Region(outline);previous?.Dispose();
        backdrop?.Dispose();backdrop=new Bitmap(Width,Height);
        using var g=Graphics.FromImage(backdrop);g.SmoothingMode=SmoothingMode.AntiAlias;
        using var bg=new LinearGradientBrush(new Rectangle(0,0,Width,Height),Color.FromArgb(23,47,66),Color.FromArgb(13,22,42),125);g.FillRectangle(bg,0,0,Width,Height);
        void Glow(float x,float y,float size,Color c){using var ellipse=new GraphicsPath();ellipse.AddEllipse(x,y,size,size);using var glow=new PathGradientBrush(ellipse){CenterColor=c,SurroundColors=new[]{Color.FromArgb(0,c)}};g.FillPath(glow,ellipse);}
        Glow(-Width*.45f,-100,Width*1.65f,Color.FromArgb(105,28,150,165));
        Glow(Width*.3f,Height*.28f,Width*1.4f,Color.FromArgb(64,103,80,168));
        Glow(-180,Height*.7f,Width*1.2f,Color.FromArgb(38,22,131,177));Invalidate();
    }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if(backdrop!=null)e.Graphics.DrawImageUnscaled(backdrop,0,0);else base.OnPaintBackground(e);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        using var path=Glass.Round(new RectangleF(.6f,.6f,Width-1.4f,Height-1.4f),32);
        using var edge=new LinearGradientBrush(ClientRectangle,Color.FromArgb(150,218,251,255),Color.FromArgb(30,167,187,230),120);
        using var pen=new Pen(edge);e.Graphics.DrawPath(pen,path);
    }
    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if(m.Msg==0x84 && m.Result==(IntPtr)1){var point=PointToClient(new Point((short)(m.LParam.ToInt64()&65535),(short)(m.LParam.ToInt64()>>16)));if(point.Y<72)m.Result=(IntPtr)2;}
    }
    protected override void Dispose(bool disposing){if(disposing)backdrop?.Dispose();base.Dispose(disposing);}
}
