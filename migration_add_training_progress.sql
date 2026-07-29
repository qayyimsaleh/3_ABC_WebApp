USE [ABC]
GO

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name='training_progress' AND schema_id=SCHEMA_ID('dbo'))
BEGIN
    CREATE TABLE [dbo].[training_progress] (
        [EmployeeID]  [nvarchar](50)  NOT NULL,
        [Part]        [int]           NOT NULL,
        [TrainingYear][int]           NOT NULL,
        [SlideIndex]  [int]           NOT NULL CONSTRAINT [DF_training_progress_SlideIndex] DEFAULT (0),
        [SlideId]     [nvarchar](100) NULL,
        [Lang]        [nvarchar](20)  NULL     CONSTRAINT [DF_training_progress_Lang]       DEFAULT ('english'),
        [LastUpdated] [datetime]      NULL     CONSTRAINT [DF_training_progress_LastUpdated] DEFAULT (GETDATE()),
        CONSTRAINT [PK_training_progress] PRIMARY KEY CLUSTERED (
            [EmployeeID]   ASC,
            [Part]         ASC,
            [TrainingYear] ASC
        )
    )
    PRINT 'training_progress table created.'
END
ELSE
    PRINT 'training_progress table already exists — skipped.'
GO
