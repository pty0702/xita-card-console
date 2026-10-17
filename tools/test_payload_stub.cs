// 测试载荷只验证进程启动，不打开窗口或访问外部资源。
internal static class TestPayloadStub
{
    private static int Main()
    {
        return 0;
    }
}
