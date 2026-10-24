import asyncio

from ...runner import EventBus, Runner


class AsyncRunner(Runner):
    """异步 HTTP 用例入口；把遗留文件/容器流水线移出 FastAPI 事件循环。"""

    async def astart(self, project_id: int) -> None:
        await asyncio.to_thread(self.start, project_id)

    async def astop(self, project_id: int) -> None:
        await asyncio.to_thread(self.stop, project_id)

    async def adelete(self, project_id: int) -> None:
        await asyncio.to_thread(self.delete, project_id)


__all__ = ["AsyncRunner", "EventBus"]
